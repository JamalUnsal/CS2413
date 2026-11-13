"""Exception types shared across the authentication prototype."""

from __future__ import annotations


class AuthSystemError(Exception):
    """Base class for expected, handled errors in the prototype."""


class StorageError(AuthSystemError):
    """A storage backend could not complete an operation."""


class IntegrityError(StorageError):
    """Stored credential data failed the HMAC integrity check.

    When this is raised the data MUST NOT be trusted or modified; the caller
    should refuse the operation and surface the problem to the operator.
    """


class PolicyError(AuthSystemError):
    """A password failed policy validation (placeholder for Hazem's module)."""


class MfaError(AuthSystemError):
    """A multi-factor authentication operation failed."""


class NotConfiguredError(AuthSystemError):
    """Raised by placeholder modules whose owner has not implemented them yet."""
