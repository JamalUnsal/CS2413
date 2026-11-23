"""Experiment 2 - Hashing algorithm comparison.

OWNER: Hazem Alfeky.

STATUS: IMPLEMENTED.

"""

from __future__ import annotations

import hashlib
import os
import random
import time
from pathlib import Path

import bcrypt
import matplotlib.pyplot as plt
from argon2 import PasswordHasher

from auth_system.passwords import hash_password, prepare_password

BLOCKLIST_PATH = Path("data/blocklist.txt")
CHART_PATH = Path("experiments/exp02_hashing_comparison.png")
argon2_hasher = PasswordHasher()


def hash_value(scheme: str, password: str) -> str:
    if scheme == "plaintext":
        return password
    if scheme == "md5_unsalted":
        return hashlib.md5(password.encode()).hexdigest()
    if scheme == "sha256_unsalted":
        return hashlib.sha256(password.encode()).hexdigest()
    if scheme == "sha256_salted":
        salt = os.urandom(16).hex()
        digest = hashlib.sha256((salt + password).encode()).hexdigest()
        return f"{salt}:{digest}"
    if scheme == "pbkdf2_sha256":
        salt = os.urandom(16).hex()
        digest = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt), 200_000).hex()
        return f"{salt}:{digest}"
    if scheme == "bcrypt_r8":
        return hash_password(password, rounds=8)
    if scheme == "bcrypt_r10":
        return hash_password(password, rounds=10)
    if scheme == "bcrypt_r12":
        return hash_password(password, rounds=12)
    if scheme == "argon2id":
        return argon2_hasher.hash(password)
    raise ValueError(scheme)


def check_value(scheme: str, password: str, stored: str) -> bool:
    if scheme == "sha256_salted":
        salt, digest = stored.split(":")
        return hashlib.sha256((salt + password).encode()).hexdigest() == digest
    if scheme == "pbkdf2_sha256":
        salt, digest = stored.split(":")
        return hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt), 200_000).hex() == digest
    if scheme in ("bcrypt_r8", "bcrypt_r10", "bcrypt_r12"):
        return bcrypt.checkpw(prepare_password(password), stored.encode("ascii"))
    if scheme == "argon2id":
        try:
         return argon2_hasher.verify(stored, password)
        except Exception:
         return False
    return hash_value(scheme, password) == stored


def main() -> int:
    wordlist = [
        line.strip()
        for line in BLOCKLIST_PATH.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.startswith("#")
    ]

    rng = random.Random(42)
    accounts = rng.sample(wordlist, 70) + [f"StrongPass!{i}#Galaxy" for i in range(30)]
    rng.shuffle(accounts)

    schemes = [
        "plaintext",
        "md5_unsalted",
        "sha256_unsalted",
        "sha256_salted",
        "pbkdf2_sha256",
        "bcrypt_r8",
        "bcrypt_r10",
        "bcrypt_r12",
        "argon2id",
    ]

    cracked_results = []

    for scheme in schemes:
        t0 = time.perf_counter()
        hash_value(scheme, "Tr0ub4dor&3!Galaxy")
        hash_ms = (time.perf_counter() - t0) * 1000

        
        stored_hashes = [hash_value(scheme, pw) for pw in accounts]


        cracked = 0
        start = time.perf_counter()

        if scheme in ("plaintext", "md5_unsalted", "sha256_unsalted"):
            lookup = {hash_value(scheme, word) for word in wordlist}
            for h in stored_hashes:
                if h in lookup:
                    cracked += 1
        else:
            for h in stored_hashes:
                for word in wordlist:
                    if time.perf_counter() - start >= 2.0:
                        break
                    if check_value(scheme, word, h):
                        cracked += 1
                        break
                if time.perf_counter() - start >= 2.0:
                    break

        elapsed = time.perf_counter() - start
        cracked_results.append(cracked)
        print(f"[{scheme}] hash_time={hash_ms:.2f} ms | cracked={cracked}/100 in {elapsed:.2f}s")

  
    plt.figure(figsize=(10, 5))
    plt.barh(schemes, cracked_results, color="steelblue")
    plt.xlim(0, 100)
    plt.xlabel("Accounts Cracked in <= 2s (out of 100)")
    plt.title("Offline Dictionary Attack Success by Hashing Scheme")
    plt.gca().invert_yaxis()
    plt.tight_layout()
    plt.savefig(CHART_PATH)
    print(f"\nChart saved to {CHART_PATH}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
