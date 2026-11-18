#!/usr/bin/env python3
"""
Dictionary Attack Script
OWNER: Jennifer Cruza

Automated dictionary attack harness testing authentication resilience
against candidate wordlists (e.g. RockYou subset).
"""

import argparse
import os
import sys
import time
from pathlib import Path
from typing import Dict, Any, List, Optional

# ensure project root is in Python path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

DEFAULT_WORDLIST = [
    "123456", "password", "123456789", "12345678", "12345",
    "qwerty", "password123", "dragon", "admin", "welcome",
    "P@ssword123!", "Secur3P@ss2026!", "RockYouSubset2026", "alice123"
]

def run_dictionary_attack(
    login_func,
    target_user: str = "alice",
    wordlist_path: Optional[str] = None,
    max_attempts: int = 100,
    delay: float = 0.0
) -> Dict[str, Any]:
    print("\n" + "="*70)
    print(f"  EXPERIMENT 5: AUTOMATED DICTIONARY ATTACK (Target: '{target_user}')")
    print("="*70)

    candidates = []
    if wordlist_path and os.path.exists(wordlist_path):
        print(f"[*] Reading wordlist: {wordlist_path}")
        with open(wordlist_path, "r", encoding="utf-8", errors="ignore") as f:
            candidates = [line.strip() for line in f if line.strip()]
    else:
        print("[*] Using default candidate wordlist subset.")
        candidates = DEFAULT_WORDLIST

    candidates = candidates[:max_attempts]
    print(f"[*] Starting attack with {len(candidates)} candidate passwords...\n")

    attempts = 0
    successful_password = None
    lockout_occurred = False
    start_time = time.time()
    latencies = []

    for candidate in candidates:
        attempts += 1
        if delay > 0:
            time.sleep(delay)
        
        req_start = time.time()
        res = login_func(target_user, candidate)
        req_latency = time.time() - req_start
        latencies.append(req_latency)

        # normalize response formats
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
            print(f"  [Attempt {attempts:03d}] Candidate: '{candidate:<16}' -> RESULT: ACCOUNT LOCKED OUT!")
            break

        if success:
            successful_password = candidate
            print(f"  [Attempt {attempts:03d}] Candidate: '{candidate:<16}' -> RESULT: SUCCESS! Password cracked!")
            break

        print(f"  [Attempt {attempts:03d}] Candidate: '{candidate:<16}' -> RESULT: REJECTED ({message})")

    total_time = time.time() - start_time
    avg_latency = (sum(latencies) / len(latencies)) if latencies else 0.0

    print("-" * 70)
    print("DICTIONARY ATTACK EVALUATION SUMMARY:")
    print(f"  • Target Username       : {target_user}")
    print(f"  • Total Attempts Made   : {attempts}")
    print(f"  • Elapsed Time          : {total_time:.4f} seconds")
    print(f"  • Average Latency/Req   : {avg_latency * 1000:.2f} ms")
    print(f"  • Account Locked Out    : {'YES (Defense Working)' if lockout_occurred else 'NO'}")
    print(f"  • Attack Success Status : {'CRACKED' if successful_password else 'BLOCKED / UNSUCCESSFUL'}")
    if successful_password:
        print(f"  • Recovered Password    : '{successful_password}'")
    print("=" * 70 + "\n")

    return {
        "target_user": target_user,
        "attempts": attempts,
        "total_time_sec": total_time,
        "avg_latency_sec": avg_latency,
        "lockout_occurred": lockout_occurred,
        "success": bool(successful_password),
        "recovered_password": successful_password
    }

def main():
    parser = argparse.ArgumentParser(description="Dictionary Attack Tool (CS2413 Team 9 - Jennifer Cruza)")
    parser.add_argument("--target-user", default="alice", help="Target username for dictionary attack.")
    parser.add_argument("--wordlist", default=None, help="Path to wordlist file.")
    parser.add_argument("--max-attempts", type=int, default=50, help="Max candidates to test.")
    parser.add_argument("--delay", type=float, default=0.0, help="Delay between attempts in seconds.")
    args = parser.parse_args()

    # dynamic import of auth service if available, otherwise mock
    try:
        from auth_system.verification import login
        login_func = login
    except ImportError:
        def mock_login(username, password):
            if password == "Secur3P@ss2026!":
                return {"success": True, "message": "Authenticated."}
            return {"success": False, "message": "Invalid password."}
        login_func = mock_login

    run_dictionary_attack(login_func, target_user=args.target_user, wordlist_path=args.wordlist, max_attempts=args.max_attempts, delay=args.delay)

if __name__ == "__main__":
    main()
