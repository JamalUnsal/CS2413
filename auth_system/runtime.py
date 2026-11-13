"""Object wiring for the prototype (composition root).

Keeps CLI, experiments and tests from constructing services by hand.  Swap the
lockout strategy here when Jamal's implementations land; swap the audit log here
when Jamal's file-backed logger lands.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Callable

from auth_system.audit import AuditLog, NullAuditLog
from auth_system.auth import AuthService
from auth_system.config import Settings
from auth_system.credentials import CredentialManager
from auth_system.lockout import LockoutPolicy, NoLockoutPolicy
from auth_system.mfa import MfaService
from auth_system.policy import PasswordPolicy
from auth_system.registration import RegistrationService
from auth_system.sessions import SessionManager
from auth_system.storage import StorageBackend, create_storage


@dataclass
class Runtime:
    settings: Settings
    storage: StorageBackend
    sessions: SessionManager
    mfa: MfaService
    lockout: LockoutPolicy
    audit: AuditLog
    auth: AuthService
    credentials: CredentialManager
    registration: RegistrationService
    clock: Callable[[], float]

    def close(self) -> None:
        self.storage.close()


def build_runtime(
    settings: Settings | None = None,
    *,
    backend: str = "json",
    audit: AuditLog | None = None,
    lockout: LockoutPolicy | None = None,
    clock: Callable[[], float] = time.time,
) -> Runtime:
    settings = settings or Settings()
    settings.data_dir.mkdir(parents=True, exist_ok=True)

    # NOTE: the file-backed AuditLog is Jamal's placeholder; the null logger
    # keeps the rest of the system runnable in the meantime.
    audit = audit or NullAuditLog()

    storage = create_storage(backend, settings, audit=audit)
    sessions = SessionManager(
        ttl_seconds=settings.session_ttl_seconds,
        token_bytes=settings.session_token_bytes,
        clock=clock,
    )
    mfa = MfaService(settings, clock=clock)
    lockout = lockout or NoLockoutPolicy()
    policy = PasswordPolicy(settings)

    return Runtime(
        settings=settings,
        storage=storage,
        sessions=sessions,
        mfa=mfa,
        lockout=lockout,
        audit=audit,
        auth=AuthService(storage, sessions, mfa, lockout, audit, settings, clock=clock),
        credentials=CredentialManager(
            storage, sessions, audit, settings, policy=policy, clock=clock
        ),
        registration=RegistrationService(
            storage, policy, audit, settings, clock=clock
        ),
        clock=clock,
    )
