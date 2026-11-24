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
