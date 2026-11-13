"""Test helpers (not fixtures)."""

from __future__ import annotations

from auth_system import devtools
from auth_system.credentials import CredentialManager
from auth_system.policy import PolicyResult
from auth_system.runtime import Runtime


class FakeClock:
    def __init__(self, now: float = 1_700_000_000.0) -> None:
        self.now = now

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


class FakePolicy:
    """Minimal deterministic policy double for credential-flow tests."""

    def __init__(self, blocked_words: tuple[str, ...] = ("blocked",)) -> None:
        self.blocked_words = blocked_words
        self.calls: list[tuple[str, str]] = []

    def validate_password(self, username: str, password: str) -> PolicyResult:
        self.calls.append((username, password))
        reasons: list[str] = []
        if len(password) < 8:
            reasons.append("Password must be at least 8 characters long.")
        if any(word in password.lower() for word in self.blocked_words):
            reasons.append("Password contains a blocked word.")
        if username.lower() in password.lower():
            reasons.append("Password must not contain the username.")
        return PolicyResult(ok=not reasons, reasons=tuple(reasons))


def make_credentials(runtime: Runtime, policy: FakePolicy | None = None) -> CredentialManager:
    """CredentialManager wired to real bcrypt (cheap rounds) but a fake policy."""
    return CredentialManager(
        runtime.storage,
        runtime.sessions,
        runtime.audit,
        runtime.settings,
        policy=policy or FakePolicy(),
        hasher=lambda password: devtools.dev_hash_password(
            password, runtime.settings.bcrypt_rounds
        ),
        clock=runtime.clock,
    )


def seed(runtime: Runtime, username: str, password: str, **kwargs: object):
    return devtools.seed_user(
        runtime.storage,
        username,
        password,
        rounds=runtime.settings.bcrypt_rounds,
        clock=runtime.clock,
        **kwargs,
    )
