"""TOTP-based multi-factor authentication.

Uses ``pyotp`` for RFC 6238 TOTP and returns an ``otpauth://`` provisioning URI
that any authenticator app can import (or render as a QR code).  Code-attempt
limiting lives in :mod:`auth_system.auth`, where the user record is available.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Callable

import pyotp

from auth_system.config import Settings

INVALID_MFA_MESSAGE = "Invalid or missing verification code."


@dataclass(frozen=True)
class MfaEnrollment:
    secret: str
    provisioning_uri: str


class MfaService:
    def __init__(
        self,
        settings: Settings,
        *,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self.settings = settings
        self._clock = clock

    # ------------------------------------------------------------------
    # Enrollment
    # ------------------------------------------------------------------
    def enrollment_for(self, username: str) -> MfaEnrollment:
        """Create a new secret and a QR-compatible provisioning URI.

        The secret is *not* enabled until the user proves possession by
        entering a valid code (``AuthService.confirm_mfa_enrollment``).
        """
        secret = pyotp.random_base32()
        return MfaEnrollment(
            secret=secret,
            provisioning_uri=self.provisioning_uri(username, secret),
        )

    def provisioning_uri(self, username: str, secret: str) -> str:
        totp = self._totp(secret)
        return totp.provisioning_uri(name=username, issuer_name=self.settings.mfa_issuer)

    # ------------------------------------------------------------------
    # Verification
    # ------------------------------------------------------------------
    def normalize_code(self, code: object) -> str | None:
        """Trim separators and validate shape; return ``None`` when malformed."""
        if not isinstance(code, str):
            return None
        cleaned = code.strip().replace(" ", "").replace("-", "")
        if not cleaned.isdigit():
            return None
        if len(cleaned) != self.settings.mfa_digits:
            return None
        return cleaned

    def verify_code(self, secret: str, code: object, *, at: float | None = None) -> bool:
        """Verify a TOTP code, allowing the configured clock-skew window."""
        normalized = self.normalize_code(code)
        if not secret or normalized is None:
            return False
        try:
            totp = self._totp(secret)
            when = self._clock() if at is None else at
            return bool(totp.verify(normalized, for_time=when, valid_window=self.settings.mfa_valid_window))
        except (ValueError, TypeError):
            # Invalid base32 secret or malformed time -> treat as a failed code.
            return False

    def generate_code(self, secret: str, *, at: float | None = None) -> str:
        """Convenience for demos/tests: current code for ``secret``."""
        when = self._clock() if at is None else at
        return self._totp(secret).at(when)

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------
    def _totp(self, secret: str) -> pyotp.TOTP:
        return pyotp.TOTP(
            secret,
            digits=self.settings.mfa_digits,
            interval=self.settings.mfa_interval_seconds,
        )
