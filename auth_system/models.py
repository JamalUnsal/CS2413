"""The shared user-record schema (JSON and SQLite backends store this shape).

Field list follows Section 5 of the proposal: username, password hash,
per-user salt (kept for comparison schemes; bcrypt embeds its salt), lockout
state, TOTP secret, reset-token state and timestamps.

`password_hash` is the only secret material needed to verify a password.
`totp_secret` is stored in the same record for the prototype; in production it
would live in a dedicated secret store.
"""

from __future__ import annotations

import dataclasses
from dataclasses import dataclass
from typing import Any

SCHEMA_VERSION = 1


@dataclass
class UserRecord:
    username: str
    password_hash: str = ""
    salt: str | None = None

    # --- lockout state (written by the lockout policy, owner: Jamal) --------
    failed_attempts: int = 0
    lockout_until: float | None = None

    # --- MFA state (owner: Sandeep) -----------------------------------------
    totp_secret: str | None = None
    mfa_enabled: bool = False
    mfa_failed_attempts: int = 0
    mfa_locked_until: float | None = None

    # --- reset-token state (owner: Shalom) ----------------------------------
    reset_token_hash: str | None = None
    reset_token_expires_at: float | None = None

    # --- bookkeeping --------------------------------------------------------
    created_at: float = 0.0
    updated_at: float = 0.0
    password_changed_at: float = 0.0

    def copy(self) -> "UserRecord":
        """Return a detached copy so callers cannot mutate storage state."""
        return dataclasses.replace(self)

    def is_locked_out(self, now: float) -> bool:
        return self.lockout_until is not None and self.lockout_until > now

    def is_mfa_locked_out(self, now: float) -> bool:
        return self.mfa_locked_until is not None and self.mfa_locked_until > now

    def to_dict(self) -> dict[str, Any]:
        return dataclasses.asdict(self)

    @classmethod
    def from_dict(cls, data: Any) -> "UserRecord":
        """Rebuild a record, tolerating missing optional fields.

        Raises ``ValueError`` for structurally invalid data.  Note that this is
        not a security boundary: the HMAC check in the storage layer is what
        establishes trust in the record.
        """
        if not isinstance(data, dict):
            raise ValueError("user record must be a JSON object")

        username = data.get("username")
        if not isinstance(username, str) or not username.strip():
            raise ValueError("user record is missing a valid username")

        password_hash = data.get("password_hash", "")
        if not isinstance(password_hash, str):
            raise ValueError("password_hash must be a string")

        return cls(
            username=username,
            password_hash=password_hash,
            salt=_optional_str(data.get("salt")),
            failed_attempts=_as_int(data.get("failed_attempts"), 0),
            lockout_until=_optional_float(data.get("lockout_until")),
            totp_secret=_optional_str(data.get("totp_secret")),
            mfa_enabled=bool(data.get("mfa_enabled", False)),
            mfa_failed_attempts=_as_int(data.get("mfa_failed_attempts"), 0),
            mfa_locked_until=_optional_float(data.get("mfa_locked_until")),
            reset_token_hash=_optional_str(data.get("reset_token_hash")),
            reset_token_expires_at=_optional_float(data.get("reset_token_expires_at")),
            created_at=_as_float(data.get("created_at"), 0.0),
            updated_at=_as_float(data.get("updated_at"), 0.0),
            password_changed_at=_as_float(data.get("password_changed_at"), 0.0),
        )


def _optional_str(value: Any) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise ValueError("expected a string or null")
    return value


def _as_int(value: Any, default: int) -> int:
    if value is None:
        return default
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError("expected an integer")
    return int(value)


def _as_float(value: Any, default: float) -> float:
    if value is None:
        return default
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError("expected a number")
    return float(value)


def _optional_float(value: Any) -> float | None:
    if value is None:
        return None
    return _as_float(value, 0.0)
