"""Dictionary attack script.

OWNER: Jennifer Cruza.

STATUS: NOT IMPLEMENTED. This file is a handoff placeholder that defines the
command-line contract the attack harness (Experiment 5, Jamal) can drive.

Planned behaviour:
  * stream candidate passwords from a wordlist (``data/blocklist.txt`` by
    default, or a larger public leaked-password subset);
  * call ``AuthService.login`` for each candidate against the prototype's own
    synthetic account;
  * respect the lockout policy (stop when ``reason == "locked_out"``);
  * report guesses used, wall time, whether the password was recovered, and the
    audit-event summary.

Run: ``python tools/attack_dictionary.py --help``
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

# Support direct execution: ``python tools/attack_dictionary.py``.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Online dictionary attack simulation (placeholder).")
    parser.add_argument("--data-dir", default="data", help="prototype data directory")
    parser.add_argument("--backend", choices=("json", "sqlite"), default="json")
    parser.add_argument("--username", default="demo-user", help="account under attack")
    parser.add_argument("--wordlist", default="data/blocklist.txt")
    parser.add_argument("--max-attempts", type=int, default=1000)
    parser.add_argument("--delay", type=float, default=0.0, help="seconds between guesses")
    return parser


def main(argv: list[str] | None = None) -> int:
    build_parser().parse_args(argv)
    print("Dictionary attack script: NOT IMPLEMENTED (owner: Jennifer Cruza)")
    print("See the module docstring for the planned behaviour and CLI contract.")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
