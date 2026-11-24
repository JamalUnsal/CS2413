from __future__ import annotations

import bcrypt

from auth_system.passwords import prepare_password

# Single generic message for every credential failure: wrong username, wrong
# password, empty input or malformed record.
INVALID_CREDENTIALS_MESSAGE = "Invalid username or password."

# bcrypt hashes of "team9-dummy-password-not-used-anywhere" prepared with the
# same SHA-256 + base64 scheme as real hashes.  They match no account.  Keeping
# one per work factor lets tests/experiments run at low cost while matching the
# real verification cost (otherwise unknown usernames would be *slower*).
DUMMY_HASH = "$2b$12$3du3hELPvTEExOZaJ9sgr.6QEHBHcGOGanq378nihofjoRQqaoMS2"
DUMMY_HASHES = {
    4: "$2b$04$hpT3YM45ADStmervMWgxSOfTqMSedxF8pB2/uAGs2sYTDidQQLh9e",
    12: DUMMY_HASH,
}


def verify_password(stored_hash: str, password: str) -> bool:
    """Constant-time bcrypt check of ``password`` against ``stored_hash``.

    Returns ``False`` (never raises) for empty/malformed hashes, non-string
    passwords or invalid bcrypt input, so malformed stored data cannot crash
    the login path or leak a distinct error.
    """
    if not isinstance(stored_hash, str) or not stored_hash:
        return False
    if not isinstance(password, str):
        return False
    try:
        return bcrypt.checkpw(prepare_password(password), stored_hash.encode("utf-8"))
    except (ValueError, TypeError):
        return False


def dummy_hash_for(rounds: int) -> str:
    """Dummy hash whose bcrypt cost matches the configured work factor."""
    return DUMMY_HASHES.get(rounds, DUMMY_HASH)


def dummy_verify(password: str, rounds: int = 12) -> None:
    """Burn the same bcrypt work as a real verification for unknown users."""
    dummy_hash = dummy_hash_for(rounds)
    try:
        bcrypt.checkpw(
            prepare_password(password if isinstance(password, str) else ""),
            dummy_hash.encode("ascii"),
        )
    except (ValueError, TypeError):
        return None
