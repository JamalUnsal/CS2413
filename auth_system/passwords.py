"""Password hashing.

OWNER: Hazem Alfeky ("initial bcrypt hashing setup", Experiment 2).

STATUS: placeholder - ``hash_password`` must still be implemented.

Integration contract
---------------------
Hashing and verification must use the same input encoding.  bcrypt only reads
the first 72 bytes of its input, which silently truncates long passphrases and
is a known footgun.  The shared helper :func:`prepare_password` pre-hashes the
UTF-8 password with SHA-256 and base64-encodes the digest (44 bytes), so the
full password always contributes to the hash.  ``auth_system.verification``
(Sandeep) imports this helper; Hazem's implementation must use it too.

Suggested implementation::

    return bcrypt.hashpw(
        prepare_password(password), bcrypt.gensalt(rounds=rounds)
    ).decode("ascii")

The salt is embedded in the bcrypt string, so ``UserRecord.salt`` stays empty
for bcrypt.  The scheme identifier (``$2b$``) and work factor are also embedded,
which makes ``needs_rehash`` possible.
"""

from __future__ import annotations

import base64
import hashlib


def prepare_password(password: str) -> bytes:
    """Normalise a password for bcrypt (shared hashing/verification contract).

    This is implemented here, in the hashing module, because both the hasher
    (Hazem) and the verifier (Sandeep) must agree on it.  Changing the scheme
    later requires re-hashing users, so treat it as a storage-format decision.
    """
    if not isinstance(password, str):
        raise TypeError("password must be a string")
    return base64.b64encode(hashlib.sha256(password.encode("utf-8")).digest())


def hash_password(password: str, rounds: int = 12) -> str:
    """Return a salted bcrypt hash for ``password``.

    TODO(Hazem Alfeky): implement with ``bcrypt.hashpw`` + ``bcrypt.gensalt``
    using :func:`prepare_password` and validate ``4 <= rounds <= 31``.
    """
    raise NotImplementedError(
        "Password hashing is not implemented yet."
    )


def needs_rehash(stored_hash: str, rounds: int) -> bool:
    """Return True when ``stored_hash`` uses a weaker cost than ``rounds``.

    TODO(Hazem Alfeky): parse the bcrypt cost field and compare it.
    """
    raise NotImplementedError(
        "Re-hash detection is not implemented yet."
    )
