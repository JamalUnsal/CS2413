"""Temporary devtool for putting a user directly into storage. not for the final submission.  This is just for testing and development purposes.  It bypasses the normal registration flow and password policy, so it should not be used in production or in any security-sensitive context.
"""

from __future__ import annotations

import time
from typing import Callable

import bcrypt

from auth_system.models import UserRecord
from auth_system.passwords import prepare_password
from auth_system.storage.base import StorageBackend


def dev_hash_password(password: str, rounds: int = 4) -> str:
    """Hash a password for seeding only.  Bypasses the registration policy."""
    if rounds < 4:
        raise ValueError("bcrypt requires at least 4 rounds")
    return bcrypt.hashpw(prepare_password(password), bcrypt.gensalt(rounds=rounds)).decode("ascii")


def seed_user(
    storage: StorageBackend,
    username: str,
    password: str,
    *,
    rounds: int = 4,
    mfa_secret: str | None = None,
    mfa_enabled: bool = False,
    failed_attempts: int = 0,
    lockout_until: float | None = None,
    clock: Callable[[], float] = time.time,
) -> UserRecord:
    """Create (or replace) a demo account directly in ``storage``."""
    now = clock()
    user = UserRecord(
        username=username,
        password_hash=dev_hash_password(password, rounds=rounds),
        failed_attempts=failed_attempts,
        lockout_until=lockout_until,
        totp_secret=mfa_secret,
        mfa_enabled=mfa_enabled,
        created_at=now,
        updated_at=now,
        password_changed_at=now,
    )
    storage.save_user(user)
    return user
