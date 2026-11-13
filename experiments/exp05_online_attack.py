"""Experiment 5 - Online brute-force and dictionary attack simulation.

OWNER: Jamal Unsal (assisted by Jennifer Cruza for the attack scripts).

STATUS: NOT IMPLEMENTED. This file is a handoff placeholder.

Planned procedure (proposal Section 6, Experiment 5):
  * Run automated attacks against ``AuthService.login`` in three configurations:
    no protection (``NoLockoutPolicy`` stand-in), ``FixedLockoutPolicy`` and
    ``ExponentialBackoffPolicy``.
  * Use both a generated brute-force guess stream and the dictionary wordlist
    from ``tools/attack_dictionary.py``.
  * Measure guesses before blocking, total time and whether the correct
    password was found.
  * Use the audit log as evidence (integrity + lockout events).

The attack scripts themselves live in ``tools/attack_bruteforce.py`` and
``tools/attack_dictionary.py`` (Jennifer's placeholders). This experiment should
drive the same login API and parameterise the lockout policy via
``auth_system.runtime.build_runtime(..., lockout=...)``.

Run: ``python -m experiments.exp05_online_attack``
"""

from __future__ import annotations


def main() -> int:
    print("Experiment 5 - Online attack simulation: NOT IMPLEMENTED (owner: Jamal Unsal)")
    print("See the module docstring for the planned procedure.")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
