"""HMAC integrity protection for stored credential data.
  * A 32-byte key is created once and stored OUTSIDE the credential file.
  * The keyed digest covers the canonical JSON encoding of the whole user
    payload (schema version + users), so *any* change is detected: swapping a
    hash, resetting a failed-attempt counter, deleting a lockout, injecting or
    removing a user.
  * Verification uses ``hmac.compare_digest`` (constant time).
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
from pathlib import Path
from typing import Any, Mapping

from auth_system.errors import IntegrityError

KEY_BYTES = 32
ALGORITHM = "HMAC-SHA256"


def canonical_json(payload: Mapping[str, Any]) -> bytes:
    """Stable byte encoding used for signing and verification."""
    return json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


class IntegritySigner:
    """Computes and verifies HMAC-SHA256 digests over canonical JSON payloads."""

    def __init__(self, key: bytes) -> None:
        if not isinstance(key, (bytes, bytearray)) or len(key) < KEY_BYTES:
            raise ValueError(f"integrity key must be at least {KEY_BYTES} bytes")
        self._key = bytes(key)

    # -- key management --------------------------------------------------
    @classmethod
    def load_or_create(cls, key_path: str | Path, *, create: bool = True) -> "IntegritySigner":
        path = Path(key_path)
        if path.exists():
            try:
                key = bytes.fromhex(path.read_text(encoding="utf-8").strip())
            except ValueError as exc:
                raise IntegrityError(
                    f"integrity key file {path} is malformed; refusing to trust stored data"
                ) from exc
            if len(key) != KEY_BYTES:
                raise IntegrityError(
                    f"integrity key file {path} has the wrong length; refusing to trust stored data"
                )
            return cls(key)

        if not create:
            raise IntegrityError(
                f"integrity key file {path} is missing; cannot verify stored data"
            )

        path.parent.mkdir(parents=True, exist_ok=True)
        key = secrets.token_bytes(KEY_BYTES)
        path.write_text(key.hex() + "\n", encoding="utf-8")
        _restrict_permissions(path)
        return cls(key)

    # -- sign / verify ---------------------------------------------------
    def sign(self, payload: bytes) -> str:
        return hmac.new(self._key, payload, hashlib.sha256).hexdigest()

    def verify(self, payload: bytes, digest: object) -> bool:
        if not isinstance(digest, str) or not digest:
            return False
        return hmac.compare_digest(self.sign(payload), digest.lower())


def _restrict_permissions(path: Path) -> None:
    """Best-effort 0600.  Windows only honours the read-only bit, so the
    README documents that the key must not be world-readable in deployment."""
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass
