"""Account lockout, rate limiting and exponential backoff.

OWNER: Jamal Unsal (Experiments 5 and 6).

STATUS: Implemented

The login service only uses these three methods, so implementing them is the
whole integration:

``check(user, now)``
    Decide whether a login attempt may proceed.  Return
    ``LockoutDecision(allowed=False, retry_after=seconds)`` while a lockout is
    active.  Never raise for a locked account.

``register_failure(user, now)``
    Update ``user.failed_attempts`` / ``user.lockout_until`` in place and return
    the resulting decision (``locked=True`` when this failure tripped the
    threshold).  The caller persists the record.

``reset(user, now)``
    Clear ``failed_attempts`` and ``lockout_until`` after a successful login.

Strategies required by the proposal:
  * ``FixedLockoutPolicy`` - lock for ``fixed_lockout_seconds`` after
    ``lockout_threshold`` consecutive failures.
  * ``ExponentialBackoffPolicy`` - delay grows from ``backoff_base_seconds``,
    doubles per failure beyond the threshold, capped at
    ``backoff_max_seconds``.  Timed lockout only (threat T9: no permanent
    lockout).

Do the arithmetic against the injected ``now`` so Experiments 5/6 can simulate
time without sleeping.
"""


from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass

from auth_system.models import UserRecord


@dataclass(frozen=True)
class LockoutDecision:
    allowed: bool
    retry_after: float | None = None
    locked: bool = False


class LockoutPolicy(ABC):
    name: str = "abstract"

    @abstractmethod
    def check(self, user: UserRecord, now: float) -> LockoutDecision:
        """Check whether a login attempt is currently allowed."""

    @abstractmethod
    def register_failure(self, user: UserRecord, now: float) -> LockoutDecision:
        """Record a failed login attempt."""

    @abstractmethod
    def reset(self, user: UserRecord, now: float) -> None:
        """Clear the failed-login state after successful authentication."""


class FixedLockoutPolicy(LockoutPolicy):
    """Lock an account for a fixed period after the threshold is reached."""

    name = "fixed"

    def __init__(self, threshold: int = 5, lockout_seconds: int = 300) -> None:
        if threshold < 1:
            raise ValueError("threshold must be at least 1")
        if lockout_seconds <= 0:
            raise ValueError("lockout_seconds must be positive")

        self.threshold = threshold
        self.lockout_seconds = lockout_seconds

    def check(self, user: UserRecord, now: float) -> LockoutDecision:
        if user.lockout_until is not None and user.lockout_until > now:
            return LockoutDecision(
                allowed=False,
                retry_after=user.lockout_until - now,
                locked=True,
            )

        return LockoutDecision(allowed=True)

    def register_failure(self, user: UserRecord, now: float) -> LockoutDecision:
        user.failed_attempts += 1

        if user.failed_attempts >= self.threshold:
            user.lockout_until = now + self.lockout_seconds
            return LockoutDecision(
                allowed=False,
                retry_after=float(self.lockout_seconds),
                locked=True,
            )

        return LockoutDecision(allowed=True)

    def reset(self, user: UserRecord, now: float) -> None:
        user.failed_attempts = 0
        user.lockout_until = None


class ExponentialBackoffPolicy(LockoutPolicy):
    """Apply increasingly long timed lockouts after repeated failures."""

    name = "backoff"

    def __init__(
        self,
        threshold: int = 5,
        base_seconds: int = 30,
        max_seconds: int = 3600,
    ) -> None:
        if threshold < 1:
            raise ValueError("threshold must be at least 1")
        if base_seconds <= 0:
            raise ValueError("base_seconds must be positive")
        if max_seconds < base_seconds:
            raise ValueError("max_seconds must be at least base_seconds")

        self.threshold = threshold
        self.base_seconds = base_seconds
        self.max_seconds = max_seconds

    def check(self, user: UserRecord, now: float) -> LockoutDecision:
        if user.lockout_until is not None and user.lockout_until > now:
            return LockoutDecision(
                allowed=False,
                retry_after=user.lockout_until - now,
                locked=True,
            )

        return LockoutDecision(allowed=True)

    def register_failure(self, user: UserRecord, now: float) -> LockoutDecision:
        user.failed_attempts += 1

        if user.failed_attempts >= self.threshold:
            exponent = user.failed_attempts - self.threshold
            delay = min(
                self.base_seconds * (2 ** exponent),
                self.max_seconds,
            )
            user.lockout_until = now + delay

            return LockoutDecision(
                allowed=False,
                retry_after=float(delay),
                locked=True,
            )

        return LockoutDecision(allowed=True)

    def reset(self, user: UserRecord, now: float) -> None:
        user.failed_attempts = 0
        user.lockout_until = None


class NoLockoutPolicy(LockoutPolicy):
    """Temporary test strategy that does not apply lockout."""

    name = "none"

    def check(self, user: UserRecord, now: float) -> LockoutDecision:
        return LockoutDecision(allowed=True)

    def register_failure(self, user: UserRecord, now: float) -> LockoutDecision:
        return LockoutDecision(allowed=True)

    def reset(self, user: UserRecord, now: float) -> None:
        return None
