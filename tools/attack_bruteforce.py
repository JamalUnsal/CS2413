"""Brute-force attack script.

OWNER: Jennifer Cruza.

STATUS: NOT IMPLEMENTED. This file is a handoff placeholder that defines the
command-line contract the attack harness (Experiment 5, Jamal) can drive.

Planned behaviour:
  * load the synthetic user store through ``auth_system.storage.create_storage``;
  * call ``AuthService.login`` repeatedly with generated guesses (optionally
    limited by ``--max-attempts`` and ``--delay``);
  * stop when the account is locked (returned ``reason`` is ``locked_out``) or
    the guess limit is reached;
  * print guesses used, wall time, whether the password was recovered, and the
    audit-event summary.

Keep the script pointed at the prototype's own data directory only. No network
targets and no real credentials.

Run: ``python tools/attack_bruteforce.py --help``
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

# Support direct execution: ``python tools/attack_bruteforce.py``.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Online brute-force simulation (placeholder).")
    parser.add_argument("--data-dir", default="data", help="prototype data directory")
    parser.add_argument("--backend", choices=("json", "sqlite"), default="json")
    parser.add_argument("--username", default="demo-user", help="account under attack")
    parser.add_argument("--max-attempts", type=int, default=1000)
    parser.add_argument("--delay", type=float, default=0.0, help="seconds between guesses")
    parser.add_argument("--length", type=int, default=4, help="generated guess length")
    parser.add_argument(
        "--charset",
        default="abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    build_parser().parse_args(argv)
    print("Brute-force attack script: NOT IMPLEMENTED (owner: Jennifer Cruza)")
    print("See the module docstring for the planned behaviour and CLI contract.")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
