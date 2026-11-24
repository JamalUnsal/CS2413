"""Session tokens.
Properties:
  * tokens come from ``secrets.token_urlsafe`` (CSPRNG, 256 bits by default);
  * only the SHA-256 fingerprint is kept in memory, so a memory dump of the
    session table does not yield usable bearer tokens;
  * every session has an absolute expiry (no sliding renewal by default);
  * logout invalidates immediately, and ``invalidate_all`` supports password
    change/reset (Shalom's module calls it).
"""
from __future__ import annotations

import hashlib
import secrets
import time
from dataclasses import dataclass
from typing import Callable


@dataclass(frozen=True)
class Session:
    username: str
    created_at: float
    expires_at: float
    fingerprint: str

    def is_expired(self, now: float) -> bool:
        return self.expires_at <= now

    def remaining_seconds(self, now: float) -> float:
        return max(0.0, self.expires_at - now)


class SessionManager:
    def __init__(
        self,
        ttl_seconds: int = 1800,
        token_bytes: int = 32,
        *,
        clock: Callable[[], float] = time.time,
    ) -> None:
        if ttl_seconds <= 0:
            raise ValueError("session TTL must be positive")
        if token_bytes < 16:
            raise ValueError("session tokens must have at least 128 bits of entropy")
        self.ttl_seconds = ttl_seconds
        self.token_bytes = token_bytes
        self._clock = clock
        self._sessions: dict[str, Session] = {}

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------
    def create_session(self, username: str) -> tuple[str, Session]:
        """Issue a new token; return ``(raw_token, session)``.

        The raw token is returned exactly once and never stored.
        """
        if not username:
            raise ValueError("cannot create a session without a username")
        now = self._clock()
        token = secrets.token_urlsafe(self.token_bytes)
        fingerprint = _fingerprint(token)
        session = Session(
            username=username,
            created_at=now,
            expires_at=now + self.ttl_seconds,
            fingerprint=fingerprint,
        )
        self._sessions[fingerprint] = session
        return token, session

    def validate(self, token: str | None) -> Session | None:
        """Return the live session for ``token`` or ``None``."""
        if not token or not isinstance(token, str):
            return None
        fingerprint = _fingerprint(token)
        session = self._sessions.get(fingerprint)
        if session is None:
            return None
        if session.is_expired(self._clock()):
            del self._sessions[fingerprint]
            return None
        return session

    def invalidate(self, token: str | None) -> bool:
        """Log out a single token.  Returns ``True`` if it was active."""
        if not token or not isinstance(token, str):
            return False
        return self._sessions.pop(_fingerprint(token), None) is not None

    def invalidate_all(self, username: str) -> int:
        """Invalidate every session for ``username`` (password change/reset)."""
        fingerprints = [
            fingerprint
            for fingerprint, session in self._sessions.items()
            if session.username == username
        ]
        for fingerprint in fingerprints:
            del self._sessions[fingerprint]
        return len(fingerprints)

    def purge_expired(self) -> int:
        now = self._clock()
        expired = [
            fingerprint
            for fingerprint, session in self._sessions.items()
            if session.is_expired(now)
        ]
        for fingerprint in expired:
            del self._sessions[fingerprint]
        return len(expired)

    def remaining_seconds(self, session: Session) -> float:
        """Seconds left on ``session`` according to the manager's clock."""
        return session.remaining_seconds(self._clock())

    def active_sessions(self) -> list[Session]:
        """Snapshot of unexpired sessions (contains no raw tokens)."""
        self.purge_expired()
        return list(self._sessions.values())

    def __len__(self) -> int:
        return len(self._sessions)


def _fingerprint(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()
