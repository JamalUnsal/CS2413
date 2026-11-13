"""Experiment 1 - Data inspection (confidentiality).

OWNER: Jennifer Cruza.

STATUS: NOT IMPLEMENTED. This file is a handoff placeholder.

Planned procedure (proposal Section 6, Experiment 1):
  1. Register several accounts (including two with the *same* password).
  2. Print the raw JSON file.
  3. Confirm no plaintext or reversible password appears.
  4. Confirm identical passwords produce different stored hashes (unique salts).
  5. Record the result against the success criteria (0 plaintext, 0 duplicate
     hashes).

Suggested implementation: build a temporary runtime, seed accounts with known
passwords, read ``settings.users_path`` as text, and assert the password strings
are absent while ``password_hash`` values differ. Until Hazem's registration is
implemented, use ``auth_system.devtools.seed_user``.

Run: ``python -m experiments.exp01_data_inspection``
"""

from __future__ import annotations


def main() -> int:
    print("Experiment 1 - Data inspection: NOT IMPLEMENTED (owner: Jennifer Cruza)")
    print("See the module docstring for the planned procedure.")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
