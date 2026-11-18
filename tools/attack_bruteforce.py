#!/usr/bin/env python3
"""
Bruteforce Attack Tool

OWNER: Jennifer Cruza

Automated brute-force attack tool. Iterates through generated character combinations 
against the authentication system to evaluate account lockout and throttling capabilities.
"""

from __future__ import annotations
import argparse
import itertools
import os
import string
import sys
import time
from pathlib import Path
from typing import Callable, Dict, Any

# Ensure project root is in Python path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))


def parse_login_response(resp: Any) -> tuple[bool, bool, str]:
    """
    Normalizes response whether it's a dictionary or a LoginResult dataclass.
    Returns (success, locked, message).
    """
    if isinstance(resp, dict):
        success = bool(resp.get("success", False))
        locked = bool(resp.get("locked", False)) or resp.get("reason") == "locked_out"
        msg = str(resp.get("message", ""))
    else:
        success = bool(getattr(resp, "success", False))
        reason = getattr(resp, "reason", None)
        locked = (reason == "locked_out") or bool(getattr(resp, "locked", False))
        msg = str(getattr(resp, "message", ""))
    return success, locked, msg


def run_brute_force_attack(login_func: Callable[[str, str], Any],
                           target_user: str = "alice",
                           max_length: int = 4,
                           max_attempts: int = 50) -> Dict[str, Any]:
    """
    Executes automated Brute-Force Attack simulation against target login function.
    """
    print("\n" + "="*70)
    print(f"  EXPERIMENT 5: AUTOMATED BRUTE-FORCE ATTACK SIMULATION (Target: '{target_user}')")
    print("="*70)

    charset = string.ascii_lowercase + string.ascii_uppercase + string.digits
    print(f"[*] Generating brute-force candidates from charset (a-z, 0-9) up to {max_attempts} attempts...\n")

    attempts = 0
    successful_password = None
    lockout_occurred = False
    start_time = time.time()

    #generate candidate strings
    def generate_candidates():
        for length in range(1, max_length + 1):
            for combo in itertools.product(charset, repeat=length):
                yield "".join(combo)

    for candidate in generate_candidates():
        if attempts >= max_attempts:
            break

        attempts += 1
        resp = login_func(target_user, candidate)
        success, locked, msg = parse_login_response(resp)

        if locked:
            lockout_occurred = True
            print(f"  [Attempt {attempts:03d}] Brute-Force: '{candidate:<10}' -> RESULT: ACCOUNT LOCKED OUT!")
            break

        if success:
            successful_password = candidate
            print(f"  [Attempt {attempts:03d}] Brute-Force: '{candidate:<10}' -> RESULT: SUCCESS!")
            break

        print(f"  [Attempt {attempts:03d}] Brute-Force: '{candidate:<10}' -> RESULT: REJECTED")

    total_time = time.time() - start_time

    print("-" * 70)
    print("BRUTE-FORCE ATTACK EVALUATION SUMMARY:")
    print(f"  • Total Attempts Made   : {attempts}")
    print(f"  • Total Execution Time  : {total_time:.4f} seconds")
    print(f"  • Account Locked Out    : {'YES (Defense Working)' if lockout_occurred else 'NO'}")
    print(f"  • Attack Success Status : {'CRACKED' if successful_password else 'BLOCKED'}")
    print("=" * 70 + "\n")

    return {
        "attempts": attempts,
        "total_time_sec": total_time,
        "lockout_occurred": lockout_occurred,
        "success": bool(successful_password),
        "recovered_password": successful_password
    }



def main():
    parser = argparse.ArgumentParser(
        description="Experiment 5 Brute-Force Attack Tool (Jennifer Cruza)"
    )
    parser.add_argument("--target-user", default="alice", help="Target username for attack testing")
    parser.add_argument("--max-length", type=int, default=4, help="Maximum password length for combination sweep")
    parser.add_argument("--max-attempts", type=int, default=50, help="Maximum attack attempts allowed")
    args = parser.parse_args()

    # connect to authentication system
    from auth_system.runtime import build_runtime
    from auth_system.config import Settings

    settings = Settings(data_dir=PROJECT_ROOT / "data")

    runtime = build_runtime(
        settings=settings,
        backend="json"
    )

    login_fn = runtime.auth.login

    try:
        run_brute_force_attack(
            login_fn,
            target_user=args.target_user,
            max_length=args.max_length,
            max_attempts=args.max_attempts
        )
    finally:
        runtime.close()


if __name__ == "__main__":
    main()
