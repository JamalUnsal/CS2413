#!/usr/bin/env python3
"""
Brute-Force Attack Script
OWNER: Jennifer Cruza

Automated brute-force attack harness generating character combinations to test
rate-limiting, account lockout, and throttling defenses.
"""

from __future__ import annotations
import argparse
import itertools
import os
import string
import sys
import time
from pathlib import Path
from typing import Dict, Any, Optional

# ensure project root is in Python path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))


def run_brute_force_attack(
    login_func,
    target_user: str = "alice",
    max_length: int = 4,
    max_attempts: int = 50,
    delay: float = 0.0
) -> Dict[str, Any]:
    print("\n" + "="*70)
    print(f"  EXPERIMENT 5: AUTOMATED BRUTE-FORCE ATTACK (Target: '{target_user}')")
    print("="*70)

    charset = string.ascii_lowercase + string.digits
    print(f"[*] Generating brute-force candidates from charset (a-z, 0-9) up to {max_attempts} attempts...\n")

    attempts = 0
    successful_password = None
    lockout_occurred = False
    start_time = time.time()

    def generate_candidates():
        for length in range(1, max_length + 1):
            for combo in itertools.product(charset, repeat=length):
                yield "".join(combo)

    for candidate in generate_candidates():
        if attempts >= max_attempts:
            break

        attempts += 1
        if delay > 0:
            time.sleep(delay)

        res = login_func(target_user, candidate)

        # normalize response
        success = False
        message = ""
        locked = False

        if isinstance(res, dict):
            success = res.get("success", False)
            message = res.get("message", res.get("reason", ""))
            locked = res.get("locked", res.get("reason") == "locked_out")
        elif isinstance(res, tuple):
            success = res[0]
            message = str(res[1])
            locked = "locked" in message.lower()
        else:
            success = bool(res)

        if locked:
            lockout_occurred = True
            print(f"  [Attempt {attempts:03d}] Candidate: '{candidate:<10}' -> RESULT: ACCOUNT LOCKED OUT!")
            break

        if success:
            successful_password = candidate
            print(f"  [Attempt {attempts:03d}] Candidate: '{candidate:<10}' -> RESULT: SUCCESS! Password cracked!")
            break

        print(f"  [Attempt {attempts:03d}] Candidate: '{candidate:<10}' -> RESULT: REJECTED")

    total_time = time.time() - start_time

    print("-" * 70)
    print("BRUTE-FORCE ATTACK EVALUATION SUMMARY:")
    print(f"  • Target Username       : {target_user}")
    print(f"  • Total Attempts Made   : {attempts}")
    print(f"  • Total Execution Time  : {total_time:.4f} seconds")
    print(f"  • Account Locked Out    : {'YES (Defense Working)' if lockout_occurred else 'NO'}")
    print(f"  • Attack Success Status : {'CRACKED' if successful_password else 'BLOCKED'}")
    print("=" * 70 + "\n")

    return {
        "attempts": attempts,
        "total_time_sec": total_time,
        "lockout_occurred": lockout_occurred,
        "success": bool(successful_password)
    }


def main():
    parser = argparse.ArgumentParser(description="Brute-Force Attack Tool (CS2413 Team 9 - Jennifer Cruza)")
    parser.add_argument("--target-user", default="alice", help="Target username for brute-force attack.")
    parser.add_argument("--max-length", type=int, default=4, help="Maximum password character length to test.")
    parser.add_argument("--max-attempts", type=int, default=50, help="Maximum number of candidate guesses.")
    parser.add_argument("--delay", type=float, default=0.0, help="Delay between attempts in seconds.")
    args = parser.parse_args()

    # dynamic import of auth service if available, otherwise mock
    try:
        from auth_system.auth import login
        login_func = login
    except ImportError:
        def mock_login(username, password):
            print("\nMOCKING\n")
            if password == "a1":
                return {"success": True, "message": "Authenticated."}
            return {"success": False, "message": "Invalid password."}
        login_func = mock_login

    run_brute_force_attack(
        login_func,
        target_user=args.target_user,
        max_length=args.max_length,
        max_attempts=args.max_attempts,
        delay=args.delay
    )


if __name__ == "__main__":
    main()
