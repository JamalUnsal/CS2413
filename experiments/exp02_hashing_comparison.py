"""Experiment 2 - Hashing algorithm comparison.

OWNER: Hazem Alfeky.

STATUS: NOT IMPLEMENTED. This file is a handoff placeholder.

Planned procedure (proposal Section 6, Experiment 2):
  * Implement storage schemes: plaintext, unsalted MD5, unsalted SHA-256, salted
    SHA-256, PBKDF2, bcrypt (several work factors) and Argon2
    (``argon2-cffi`` is in requirements.txt but not installed yet).
  * Measure (a) time to hash one password and (b) time + success rate of an
    offline dictionary attack against 100 synthetic accounts with a fixed
    wordlist (``data/blocklist.txt`` is a starting point; use a larger public
    list for the experiment).
  * Present results as a table and a matplotlib graph; discuss why slow, salted
    hashes resist offline attacks and how bcrypt's work factor trades time for
    resistance.

Interface note: ``auth_system.passwords.prepare_password`` is the shared bcrypt
input contract used by verification; keep using it when you implement
``hash_password``.

Run: ``python -m experiments.exp02_hashing_comparison``
"""

from __future__ import annotations


def main() -> int:
    print("Experiment 2 - Hashing comparison: NOT IMPLEMENTED (owner: Hazem Alfeky)")
    print("See the module docstring for the planned procedure.")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
