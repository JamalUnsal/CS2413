"""User registration pipeline.

OWNER: Hazem Alfeky ("registration prompts", duplicate-username check,
policy enforcement and initial hashing).

STATUS: placeholder - ``register`` raises ``NotImplementedError``.

Wiring is already provided (storage, policy, audit, hasher, clock), and the CLI
menu item calls this service, so implementing ``register`` completes the
registration path end to end.  Expected behaviour:

1. Normalise/strip the username, reject empty or whitespace-only usernames and
   usernames containing control characters.
2. Reject duplicate usernames (``storage.user_exists``).
3. ``policy.validate_password`` -> on failure return the reasons and record no
   password material.
4. ``hash_password(password, rounds=settings.bcrypt_rounds)``.
5. Build a ``UserRecord`` with ``created_at``/``updated_at``/
   ``password_changed_at`` set from the injected clock, save via storage.
6. Record ``AuditEvent.REGISTRATION`` (never the password).
7. Return ``RegistrationResult(success=True, ...)``.  Do not log plaintext.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Callable

from auth_system.audit import AuditLog, AuditEvent
from auth_system.config import Settings
from auth_system.models import UserRecord 
from auth_system.passwords import hash_password
from auth_system.policy import PasswordPolicy
from auth_system.storage.base import StorageBackend


@dataclass(frozen=True)
class RegistrationResult:
    success: bool
    message: str
    reasons: tuple[str, ...] = ()


class RegistrationService:
    def __init__(
        self,
        storage: StorageBackend,
        policy: PasswordPolicy,
        audit: AuditLog,
        settings: Settings,
        *,
        hasher: Callable[[str], str] | None = None,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self.storage = storage
        self.policy = policy
        self.audit = audit
        self.settings = settings
        self._hasher = hasher or (lambda password: hash_password(password, self.settings.bcrypt_rounds))
        self._clock = clock

    def register(self, username: str, password: str) -> RegistrationResult:
        """Validate and persist a new account."""
        clean_user = username.strip()
        if not clean_user or any(ord(ch) < 32 or ord(ch) == 127 for ch in clean_user):
            return RegistrationResult(
                success=False,
                message="Invalid username.",
                reasons=("Username cannot be empty or contain control characters.",),
            )

        if self.storage.user_exists(clean_user):
            return RegistrationResult(
                success=False,
                message="Username already exists.",
                reasons=("Username is already registered.",),
            )

        verdict = self.policy.validate_password(clean_user, password)
        if not verdict.ok:
            return RegistrationResult(
                success=False,
                message=verdict.summary(),
                reasons=verdict.reasons,
            )

        pw_hash = self._hasher(password)
        now = self._clock()
        new_user = UserRecord(
            username=clean_user,
            password_hash=pw_hash,
            created_at=now,
            updated_at=now,
            password_changed_at=now,
        )
        self.storage.save_user(new_user)
        self.audit.record(AuditEvent.REGISTRATION, username=clean_user)

        return RegistrationResult(
            success=True,
            message=f"Account '{clean_user}' registered.",
        )