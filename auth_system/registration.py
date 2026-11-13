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

from auth_system.audit import AuditLog
from auth_system.config import Settings
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
        raise NotImplementedError(
            "User registration is not implemented yet."
        )
