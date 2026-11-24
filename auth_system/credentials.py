"""Credential update features: password change and secure reset flow.
Password change (proposal Section 5.6):
  * requires the current password (bcrypt verification);
  * re-applies the full password policy to the new password;
  * refuses reuse of the current password;
  * invalidates every session for the account after a successful change;
  * records an audit event (no password material).

Reset flow:
  * issues a 256-bit random token whose SHA-256 fingerprint is stored with an
    expiry (``Settings.reset_token_ttl_seconds``);
  * always returns the same message, whether or not the account exists, so the
    endpoint cannot be used for username enumeration;
  * the token is single-use: it is cleared on success;
  * the same policy, reuse check and session invalidation apply.

NOTE (prototype limitation): there is no email delivery.  ``request_password_reset``
returns the token to the caller so the CLI can print it for the demo; in a real
system it would be sent out-of-band and never displayed.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
import time
from dataclasses import dataclass
from typing import Callable

from auth_system.audit import AuditEvent, AuditLog
from auth_system.config import Settings
from auth_system.passwords import hash_password
from auth_system.policy import PasswordPolicy, PolicyResult
from auth_system.results import OperationResult
from auth_system.sessions import SessionManager
from auth_system.storage.base import StorageBackend
from auth_system.verification import verify_password

RESET_REQUEST_MESSAGE = "If that account exists, a password reset token has been issued."
INVALID_RESET_TOKEN_MESSAGE = "Invalid or expired reset token."
INCORRECT_CURRENT_PASSWORD_MESSAGE = "Current password is incorrect."
SESSION_INVALID_MESSAGE = "Your session is invalid or has expired. Please log in again."


@dataclass(frozen=True)
class PasswordResetRequest:
    message: str
    token: str | None = None


class CredentialManager:
    def __init__(
        self,
        storage: StorageBackend,
        sessions: SessionManager,
        audit: AuditLog,
        settings: Settings,
        *,
        policy: PasswordPolicy | None = None,
        hasher: Callable[[str], str] | None = None,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self.storage = storage
        self.sessions = sessions
        self.audit = audit
        self.settings = settings
        self.policy = policy or PasswordPolicy(settings)
        self._hasher = hasher or (
            lambda password: hash_password(password, settings.bcrypt_rounds)
        )
        self._clock = clock

    # ------------------------------------------------------------------
    # Change password
    # ------------------------------------------------------------------
    def change_password(
        self,
        username: str,
        old_password: str,
        new_password: str,
        *,
        session_token: str | None = None,
    ) -> OperationResult:
        normalized = (username or "").strip() if isinstance(username, str) else ""

        if session_token is not None:
            session = self.sessions.validate(session_token)
            if session is None or session.username != normalized:
                return OperationResult(False, SESSION_INVALID_MESSAGE, "invalid_session")

        user = self.storage.get_user(normalized) if normalized else None
        if user is None or not verify_password(user.password_hash, old_password):
            self.audit.record(
                AuditEvent.PASSWORD_CHANGE,
                normalized or None,
                {"result": "rejected", "reason": "bad_current_password"},
            )
            return OperationResult(False, INCORRECT_CURRENT_PASSWORD_MESSAGE, "bad_old_password")

        if verify_password(user.password_hash, new_password):
            return OperationResult(
                False,
                "New password must be different from your current password.",
                "password_reuse",
            )

        policy_result = self.policy.validate_password(normalized, new_password)
        if not policy_result.ok:
            return self._policy_failure(policy_result, reason="policy_rejected")

        user.password_hash = self._hasher(new_password)
        user.salt = None
        user.reset_token_hash = None
        user.reset_token_expires_at = None
        now = self._clock()
        user.password_changed_at = now
        user.updated_at = now
        self.storage.save_user(user)

        invalidated = self.sessions.invalidate_all(user.username)
        self.audit.record(
            AuditEvent.PASSWORD_CHANGE,
            user.username,
            {"result": "success", "sessions_invalidated": invalidated},
        )
        return OperationResult(
            True,
            "Password changed successfully. Please sign in again.",
        )

    # ------------------------------------------------------------------
    # Reset flow
    # ------------------------------------------------------------------
    def request_password_reset(self, username: str) -> PasswordResetRequest:
        normalized = (username or "").strip() if isinstance(username, str) else ""
        user = self.storage.get_user(normalized) if normalized else None

        if user is not None:
            token = secrets.token_urlsafe(32)
            user.reset_token_hash = _token_fingerprint(token)
            user.reset_token_expires_at = self._clock() + self.settings.reset_token_ttl_seconds
            user.updated_at = self._clock()
            self.storage.save_user(user)
            self.audit.record(AuditEvent.PASSWORD_RESET_REQUEST, user.username, {"issued": True})
            return PasswordResetRequest(message=RESET_REQUEST_MESSAGE, token=token)

        # Unknown account: identical response, no token, still audited.
        self.audit.record(
            AuditEvent.PASSWORD_RESET_REQUEST,
            normalized or None,
            {"issued": False},
        )
        return PasswordResetRequest(message=RESET_REQUEST_MESSAGE, token=None)

    def reset_password(
        self,
        username: str,
        token: str,
        new_password: str,
    ) -> OperationResult:
        normalized = (username or "").strip() if isinstance(username, str) else ""
        user = self.storage.get_user(normalized) if normalized else None

        if user is None or not self._reset_token_matches(user, token):
            self.audit.record(
                AuditEvent.PASSWORD_RESET,
                normalized or None,
                {"result": "rejected", "reason": "invalid_token"},
            )
            return OperationResult(False, INVALID_RESET_TOKEN_MESSAGE, "invalid_token")

        if verify_password(user.password_hash, new_password):
            return OperationResult(
                False,
                "New password must be different from your current password.",
                "password_reuse",
            )

        policy_result = self.policy.validate_password(normalized, new_password)
        if not policy_result.ok:
            # Do not consume the token: the user may retry with a valid password.
            return self._policy_failure(policy_result, reason="policy_rejected")

        user.password_hash = self._hasher(new_password)
        user.salt = None
        user.reset_token_hash = None
        user.reset_token_expires_at = None
        now = self._clock()
        user.password_changed_at = now
        user.updated_at = now
        self.storage.save_user(user)

        invalidated = self.sessions.invalidate_all(user.username)
        self.audit.record(
            AuditEvent.PASSWORD_RESET,
            user.username,
            {"result": "success", "sessions_invalidated": invalidated},
        )
        return OperationResult(
            True,
            "Password reset successfully. Please sign in with your new password.",
        )

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------
    def _reset_token_matches(self, user, token: str) -> bool:
        if not user.reset_token_hash or not user.reset_token_expires_at:
            return False
        if user.reset_token_expires_at <= self._clock():
            return False
        if not isinstance(token, str) or not token:
            return False
        return hmac.compare_digest(user.reset_token_hash, _token_fingerprint(token))

    def _policy_failure(self, result: PolicyResult, *, reason: str) -> OperationResult:
        reasons = "; ".join(result.reasons) if result.reasons else result.summary()
        return OperationResult(False, f"Password rejected: {reasons}", reason)


def _token_fingerprint(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()
