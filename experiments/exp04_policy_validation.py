"""Experiment 4 - Password policy validation.

OWNER: Hazem Alfeky.

STATUS: NOT IMPLEMENTED. This file is a handoff placeholder.

Planned procedure (proposal Section 6, Experiment 4):
  * Build a test set of at least 50 passwords covering weak, common (RockYou
    subset), medium, strong and username-containing cases.
  * Run each through ``PasswordPolicy.validate_password`` at registration.
  * Report accepted/rejected counts, every rejection reason and the zxcvbn
    strength score.
  * Check the success criterion: at least 95% of weak/common passwords rejected.

Implement after ``auth_system.policy.PasswordPolicy`` is complete; this script
then only needs to load the test set and tabulate results.

Run: ``python -m experiments.exp04_policy_validation``
"""

from __future__ import annotations


def main() -> int:
    print("Experiment 4 - Policy validation: NOT IMPLEMENTED (owner: Hazem Alfeky)")
    print("See the module docstring for the planned procedure.")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
