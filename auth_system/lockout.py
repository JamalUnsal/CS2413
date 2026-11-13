"""Account lockout, rate limiting and exponential backoff.

OWNER: Jamal Unsal (Experiments 5 and 6).

STATUS: placeholders - the two graded strategies raise ``NotImplementedError``.
``NoLockoutPolicy`` is a temporary stand-in so login works before Jamal lands
his module; it is deliberately named "none" in reports so it cannot be mistaken
for a defense.

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
        """Is this attempt currently allowed?"""

    @abstractmethod
    def register_failure(self, user: UserRecord, now: float) -> LockoutDecision:
        """Record one failed attempt and return the new decision."""

    @abstractmethod
    def reset(self, user: UserRecord, now: float) -> None:
        """Clear failure state after a successful login."""


class FixedLockoutPolicy(LockoutPolicy):
    """TODO(Jamal Unsal): fixed lockout after N failures."""

    name = "fixed"

    def __init__(self, threshold: int = 5, lockout_seconds: int = 300) -> None:
        self.threshold = threshold
        self.lockout_seconds = lockout_seconds

    def check(self, user: UserRecord, now: float) -> LockoutDecision:
        raise NotImplementedError("Fixed lockout is not implemented yet.")

    def register_failure(self, user: UserRecord, now: float) -> LockoutDecision:
        raise NotImplementedError("Fixed lockout is not implemented yet.")

    def reset(self, user: UserRecord, now: float) -> None:
        raise NotImplementedError("Fixed lockout is not implemented yet.")


class ExponentialBackoffPolicy(LockoutPolicy):
    """TODO(Jamal Unsal): timed lockout with exponential backoff."""

    name = "backoff"

    def __init__(
        self,
        threshold: int = 5,
        base_seconds: int = 30,
        max_seconds: int = 3600,
    ) -> None:
        self.threshold = threshold
        self.base_seconds = base_seconds
        self.max_seconds = max_seconds

    def check(self, user: UserRecord, now: float) -> LockoutDecision:
        raise NotImplementedError("Exponential backoff is not implemented yet.")

    def register_failure(self, user: UserRecord, now: float) -> LockoutDecision:
        raise NotImplementedError("Exponential backoff is not implemented yet.")

    def reset(self, user: UserRecord, now: float) -> None:
        raise NotImplementedError("Exponential backoff is not implemented yet.")


class NoLockoutPolicy(LockoutPolicy):
    """TEMPORARY stand-in: every attempt is allowed, no state is written.

    Exists only so the login/MFA/session work can be exercised before Jamal's
    strategies are implemented.  Replace with ``FixedLockoutPolicy`` or
    ``ExponentialBackoffPolicy`` in ``auth_system.runtime.build_runtime`` once
    they are ready.
    """

    name = "none"

    def check(self, user: UserRecord, now: float) -> LockoutDecision:
        return LockoutDecision(allowed=True)

    def register_failure(self, user: UserRecord, now: float) -> LockoutDecision:
        return LockoutDecision(allowed=True)

    def reset(self, user: UserRecord, now: float) -> None:
        return None
