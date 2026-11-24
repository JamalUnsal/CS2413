from __future__ import annotations

import base64
import hashlib
import bcrypt


def prepare_password(password: str) -> bytes:

    if not isinstance(password, str):
        raise TypeError("password must be a string")
    return base64.b64encode(hashlib.sha256(password.encode("utf-8")).digest())


def hash_password(password: str, rounds: int = 12) -> str:

    if not (4<= rounds <= 31):
        raise ValueError("rounds must be between 4 and 31")
    return bcrypt.hashpw(
        prepare_password(password), bcrypt.gensalt(rounds=rounds)
    ).decode("ascii")
   

def needs_rehash(stored_hash: str, rounds: int) -> bool:
    parts = stored_hash.split("$")
    return len(parts) != 4 or int(parts[2]) < rounds

   
