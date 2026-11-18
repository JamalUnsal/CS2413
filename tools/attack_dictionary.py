#!/usr/bin/env python3
"""
Experiment 5: Automated Dictionary Attack Simulation (attack_dictionary.py)
CS2413 - Team 9 Password Authentication System Security Design
Author/Lead: Jennifer Cruza (Assisted by Jamal Unsal)

Description:
Automated dictionary attack tool. Iterates through candidate passwords from a wordlist 
(e.g., RockYou subset) against the authentication system to evaluate lockout resilience.
"""

from __future__ import annotations
import argparse
import os
import sys
import time
from pathlib import Path
from typing import Callable, Dict, List, Optional, Any

# Ensure project root is in Python path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

# Default wordlist fallback if external file is missing
DEFAULT_WORDLIST = [
    "123456", "password", "123456789", "12345678", "12345",
    "qwerty", "password123", "dragon", "admin", "welcome",
    "P@ssword123!", "Secur3P@ss2026!", "RockYouSubset2026", "alice123"
]


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


def run_dictionary_attack(login_func: Callable[[str, str], Any],
                          target_user: str = "alice",
                          wordlist_path: Optional[str] = None,
                          max_attempts: int = 100) -> Dict[str, Any]:
    """
    Executes automated Dictionary Attack simulation against the target login function.
    """
    print("\n" + "="*70)
    print(f"  EXPERIMENT 5: AUTOMATED DICTIONARY ATTACK SIMULATION (Target: '{target_user}')")
    print("="*70)

    candidates: List[str] = []
    if wordlist_path and os.path.exists(wordlist_path):
        print(f"[*] Reading wordlist file: {wordlist_path}")
        with open(wordlist_path, "r", encoding="utf-8", errors="ignore") as f:
            candidates = [line.strip() for line in f if line.strip()]
    else:
        print("[*] No wordlist file provided; using default candidate subset.")
        candidates = DEFAULT_WORDLIST

    candidates = candidates[:max_attempts]
    print(f"[*] Starting attack with {len(candidates)} candidate passwords...\n")

    attempts = 0
    successful_password = None
    lockout_occurred = False
    start_time = time.time()
    latencies: List[float] = []

    for candidate in candidates:
        attempts += 1
        req_start = time.time()
        resp = login_func(target_user, candidate)
        req_lat = time.time() - req_start
        latencies.append(req_lat)

        success, locked, msg = parse_login_response(resp)

        if locked:
            lockout_occurred = True
            print(f"  [Attempt {attempts:03d}] Candidate: '{candidate:<16}' -> RESULT: ACCOUNT LOCKED OUT!")
            break

        if success:
            successful_password = candidate
            print(f"  [Attempt {attempts:03d}] Candidate: '{candidate:<16}' -> RESULT: SUCCESS! Password cracked!")
            break

        print(f"  [Attempt {attempts:03d}] Candidate: '{candidate:<16}' -> RESULT: REJECTED ({msg})")

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
    parser = argparse.ArgumentParser(description="Experiment 5 Dictionary Attack Tool (Jennifer Cruza)")
    parser.add_argument("--target-user", default="alice", help="Target username for attack testing.")
    parser.add_argument("--wordlist", default=None, help="Path to wordlist file.")
    parser.add_argument("--max-attempts", type=int, default=100, help="Maximum attack attempts permitted.")
    args = parser.parse_args()

    login_fn = None

    try:
        from auth_system.auth import AuthService
        print("[*] Detected live auth_system.auth.AuthService!")
        try:
            from auth_system.storage.memory import MemoryStorageBackend
            from auth_system.sessions import SessionManager
            from auth_system.mfa import MfaService
            from auth_system.lockout import AccountLockoutPolicy
            from auth_system.audit import AuditLog
            from auth_system.config import Settings

            storage = MemoryStorageBackend()
            auth_svc = AuthService(
                storage=storage,
                sessions=SessionManager(),
                mfa=MfaService(),
                lockout=AccountLockoutPolicy(),
                audit=AuditLog(),
                settings=Settings()
            )
            login_fn = auth_svc.login
        except Exception:
            pass
    except ImportError:
        pass

    if login_fn is None:
        try:
            from auth_system.auth import login as live_login
            login_fn = live_login
        except ImportError:
            try:
                from auth_system.verification import login as live_login
                login_fn = live_login
            except ImportError:
                print("[!] Live auth module not detected on sys.path; running with stateful Mock backend.")

                class StatefulMockBackend:
                    def __init__(self, lockout_threshold: int = 5):
                        self.attempts = 0
                        self.threshold = lockout_threshold

                    def login(self, username: str, password: str) -> dict[str, Any]:
                        self.attempts += 1
                        if self.attempts >= self.threshold:
                            return {"success": False, "message": "Account locked out.", "locked": True, "reason": "locked_out"}
                        return {"success": False, "message": "Invalid username or password.", "locked": False, "reason": "bad_password"}

                mock_backend = StatefulMockBackend(lockout_threshold=5)
                login_fn = mock_backend.login

    run_dictionary_attack(login_fn, target_user=args.target_user,
                          wordlist_path=args.wordlist, max_attempts=args.max_attempts)


if __name__ == "__main__":
    main()
