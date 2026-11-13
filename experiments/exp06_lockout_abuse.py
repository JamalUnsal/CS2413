"""Experiment 6 - Lockout abuse / availability test.

OWNER: Jamal Unsal.

STATUS: NOT IMPLEMENTED. This file is a handoff placeholder.

Planned procedure (proposal Section 6, Experiment 6):
  * Simulate an attacker deliberately failing logins against a legitimate
    account.
  * Measure how long the real user is locked out under ``FixedLockoutPolicy``
    versus ``ExponentialBackoffPolicy``.
  * Use an injected clock (see ``experiments._common.ExperimentClock``) so no
    real waiting is required.
  * Report the availability/security trade-off (threat T9).

Implement once the two lockout strategies exist. ``build_runtime`` already
accepts a ``lockout=`` override, and the login service persists whatever state a
policy writes into ``failed_attempts`` / ``lockout_until``.

Run: ``python -m experiments.exp06_lockout_abuse``
"""

from __future__ import annotations


def main() -> int:
    print("Experiment 6 - Lockout abuse: NOT IMPLEMENTED (owner: Jamal Unsal)")
    print("See the module docstring for the planned procedure.")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
