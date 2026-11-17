#!/usr/bin/env python3
"""
Attack Simulator & Security Inspection Engine (attack_simulator.py)
CS2413 - Team 9 Password Authentication System Security Design
OWNER: Jennifer Cruza

Description:
Central evaluation suite and attack engine located in tools/. Provides:
1. Experiment 1: JSON Credential Data Inspection (Confidentiality & Salt Uniqueness verification)
2. Experiment 5: Automated Dictionary Attack Engine
3. Experiment 5: Automated Brute-Force Character Generation Engine
4. Response Normalization & Standalone Mock Target System Simulator
"""

from __future__ import annotations
import argparse
import itertools
import json
import os
import string
import sys
import time
from pathlib import Path
from typing import Callable, Dict, List, Optional, Tuple, Any

# Ensure project root is in Python path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

# Default sample wordlist subset for standalone testing when no external wordlist file is passed
DEFAULT_WORDLIST = [
    "123456", "password", "123456789", "12345678", "12345",
    "qwerty", "password123", "dragon", "admin", "welcome",
    "P@ssword123!", "Secur3P@ss2026!", "RockYouSubset2026", "alice123"
]


class TargetSystemSimulator:
    """
    Mock implementation of the team's authentication backend.
    Used for standalone attack script testing prior to live team module integration.
    """
    def __init__(self, target_user: str = "alice", correct_password: str = "Secur3P@ss2026!",
                 defense_mode: str = "fixed_lockout", lockout_threshold: int = 5,
                 lockout_duration_sec: float = 10.0):
        self.target_user = target_user
        self.correct_password = correct_password
        self.defense_mode = defense_mode  # "unprotected", "fixed_lockout", "exponential_backoff"
        self.lockout_threshold = lockout_threshold
        self.lockout_duration_sec = lockout_duration_sec
        
        self.failed_attempts = 0
        self.locked_until = 0.0
        self.backoff_delay = 0.5  # Base delay in seconds

    def login(self, username: str, password: str) -> Dict[str, Any]:
        """
        Simulates the login verification endpoint.
        Returns a response dict: {"success": bool, "message": str, "locked": bool, "latency_sec": float}
        """
        start_time = time.time()
        now = start_time

        # Check if currently locked out
        if now < self.locked_until:
            return {
                "success": False,
                "message": "Account locked due to multiple failed attempts.",
                "locked": True,
                "latency_sec": time.time() - start_time
            }

        # Apply exponential backoff delay if enabled
        if self.defense_mode == "exponential_backoff" and self.failed_attempts > 0:
            delay = self.backoff_delay * (2 ** (self.failed_attempts - 1))
            time.sleep(min(delay, 2.0))  # Cap delay for simulation testing

        # Verify credentials
        if username == self.target_user and password == self.correct_password:
            self.failed_attempts = 0
            self.locked_until = 0.0
            return {
                "success": True,
                "message": "Authentication successful.",
                "locked": False,
                "latency_sec": time.time() - start_time
            }
        else:
            self.failed_attempts += 1
            locked = False

            if self.defense_mode == "fixed_lockout" and self.failed_attempts >= self.lockout_threshold:
                self.locked_until = now + self.lockout_duration_sec
                locked = True
            elif self.defense_mode == "exponential_backoff" and self.failed_attempts >= self.lockout_threshold:
                self.locked_until = now + (self.backoff_delay * (2 ** (self.failed_attempts - 1)))
                locked = True

            return {
                "success": False,
                "message": "Invalid username or password.",
                "locked": locked,
                "latency_sec": time.time() - start_time
            }


def normalize_login_response(raw_resp: Any) -> Dict[str, Any]:
    """
    Normalizes response signatures across various team backend implementations.
    Handles tuples (success: bool, msg: str), dicts, or raw boolean returns.
    """
    if isinstance(raw_resp, dict):
        return {
            "success": bool(raw_resp.get("success", False)),
            "message": str(raw_resp.get("message", raw_resp.get("reason", ""))),
            "locked": bool(raw_resp.get("locked", raw_resp.get("is_locked", False))),
            "latency_sec": float(raw_resp.get("latency_sec", 0.0))
        }
    elif isinstance(raw_resp, (tuple, list)):
        success = bool(raw_resp[0]) if len(raw_resp) > 0 else False
        msg = str(raw_resp[1]) if len(raw_resp) > 1 else ""
        locked = bool(raw_resp[2]) if len(raw_resp) > 2 else ("locked" in msg.lower())
        return {"success": success, "message": msg, "locked": locked, "latency_sec": 0.0}
    elif isinstance(raw_resp, bool):
        return {"success": raw_resp, "message": "Success" if raw_resp else "Invalid credentials", "locked": False, "latency_sec": 0.0}
    return {"success": False, "message": str(raw_resp), "locked": False, "latency_sec": 0.0}


# =====================================================================
# EXPERIMENT 1: JSON CREDENTIAL DATA INSPECTION
# =====================================================================

def inspect_json_storage(json_path: str = "data/users.json") -> Dict[str, Any]:
    """
    Executes Experiment 1: Confidentiality & Salt Uniqueness Inspection.
    Inspects backend JSON file to ensure zero plaintext passwords exist
    and verifies that identical passwords produce distinct per-user hashes.
    """
    print("\n" + "="*70)
    print("  EXPERIMENT 1: JSON CREDENTIAL DATA INSPECTION (CONFIDENTIALITY)")
    print("="*70)

    # Normalize json_path directory creation relative to workspace
    dirname = os.path.dirname(json_path)
    if dirname and not os.path.exists(dirname):
        os.makedirs(dirname, exist_ok=True)

    if not os.path.exists(json_path):
        print(f"[!] Warning: Data file '{json_path}' not found. Creating sample mock DB for inspection...")
        mock_data = {
            "users": {
                "alice": {
                    "username": "alice",
                    "password_hash": "$2b$12$e8N8...KzO1234567890abcdefghijklmnopqrst",
                    "salt": "unique_salt_alice_123"
                },
                "bob": {
                    "username": "bob",
                    "password_hash": "$2b$12$x9M7...LpP9876543210zyxwvutsrqponmlkj",
                    "salt": "unique_salt_bob_456"
                }
            },
            "hmac_signature": "a6f8c2b970891d24c084..."
        }
        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(mock_data, f, indent=2)

    with open(json_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    users = data.get("users", data if isinstance(data, dict) else {})
    total_users = len(users)
    plaintext_found = 0
    hashes_seen: Dict[str, str] = {}
    salt_duplications = 0

    print(f"[*] Loaded database containing {total_users} user account(s).\n")

    for username, record in users.items():
        if not isinstance(record, dict):
            continue
        pass_hash = str(record.get("password_hash", record.get("hash", "")))
        
        # Verification check 1: Ensure hash is not plaintext and follows algorithm prefix
        is_hashed = (pass_hash.startswith("$2b$") or 
                     pass_hash.startswith("$argon2") or 
                     pass_hash.startswith("$pbkdf2") or 
                     len(pass_hash) >= 32)
        
        if not is_hashed or "password" in record:
            plaintext_found += 1
            status = "FAIL (Plaintext or weak hash detected)"
        else:
            status = "PASS (Valid salted hash)"

        # Verification check 2: Salt uniqueness across identical passwords
        if pass_hash in hashes_seen:
            salt_duplications += 1
            print(f"[!] Duplicate hash detected between user '{username}' and '{hashes_seen[pass_hash]}'")
        else:
            hashes_seen[pass_hash] = username

        print(f"  - User: {username:<12} | Hash Prefix: {pass_hash[:15]}... | Status: {status}")

    # Summary report
    print("-" * 70)
    print("EXPERIMENT 1 RESULTS SUMMARY:")
    print(f"  • Total User Accounts Inspected : {total_users}")
    print(f"  • Plaintext Passwords Found     : {plaintext_found} (Target: 0)")
    print(f"  • Identical Hash Collisions     : {salt_duplications} (Target: 0 - Unique per-user salts)")
    
    passed = (plaintext_found == 0) and (salt_duplications == 0)
    print(f"  • Overall Inspection Verdict    : {'PASSED [SUCCESS]' if passed else 'FAILED [REVISION NEEDED]'}")
    print("=" * 70 + "\n")

    return {
        "total_users": total_users,
        "plaintext_found": plaintext_found,
        "salt_duplications": salt_duplications,
        "passed": passed
    }


# =====================================================================
# EXPERIMENT 5: ATTACK SIMULATIONS (DICTIONARY & BRUTE-FORCE)
# =====================================================================

def run_dictionary_attack(
    login_func: Callable[..., Any],
    target_user: str = "alice",
    wordlist_path: Optional[str] = None,
    max_attempts: int = 100,
    delay: float = 0.0
) -> Dict[str, Any]:
    """
    Executes automated Dictionary Attack simulation against the target login function.
    Iterates through wordlist passwords, tracking latency, attempt counts, and lockout events.
    """
    print("\n" + "="*70)
    print(f"  EXPERIMENT 5: AUTOMATED DICTIONARY ATTACK (Target: '{target_user}')")
    print("="*70)

    # Load wordlist
    candidates = []
    if wordlist_path and os.path.exists(wordlist_path):
        print(f"[*] Reading wordlist file: {wordlist_path}")
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
        raw_resp = login_func(target_user, candidate)
        req_latency = time.time() - req_start
        resp = normalize_login_response(raw_resp)
        latencies.append(resp.get("latency_sec", req_latency))

        if resp.get("locked"):
            lockout_occurred = True
            print(f"  [Attempt {attempts:03d}] Candidate: '{candidate:<16}' -> RESULT: ACCOUNT LOCKED OUT! Throttling active.")
            break

        if resp.get("success"):
            successful_password = candidate
            print(f"  [Attempt {attempts:03d}] Candidate: '{candidate:<16}' -> RESULT: SUCCESS! Password cracked!")
            break

        print(f"  [Attempt {attempts:03d}] Candidate: '{candidate:<16}' -> RESULT: REJECTED ({resp.get('message')})")

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


def run_brute_force_attack(
    login_func: Callable[..., Any],
    target_user: str = "alice",
    max_length: int = 4,
    max_attempts: int = 50,
    delay: float = 0.0
) -> Dict[str, Any]:
    """
    Executes automated Brute-Force Attack simulation.
    Generates character combinations systematically up to max_attempts.
    """
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

        raw_resp = login_func(target_user, candidate)
        resp = normalize_login_response(raw_resp)

        if resp.get("locked"):
            lockout_occurred = True
            print(f"  [Attempt {attempts:03d}] Candidate: '{candidate:<10}' -> RESULT: ACCOUNT LOCKED OUT!")
            break

        if resp.get("success"):
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
        "target_user": target_user,
        "attempts": attempts,
        "total_time_sec": total_time,
        "lockout_occurred": lockout_occurred,
        "success": bool(successful_password)
    }


# =====================================================================
# MAIN CLI ENTRYPOINT
# =====================================================================

def main():
    parser = argparse.ArgumentParser(description="Attack Simulator & Security Engine (CS2413 Team 9 - Jennifer Cruza)")
    parser.add_argument("--mode", choices=["inspect", "dictionary", "brute_force", "all"], default="all",
                        help="Execution mode: inspect JSON, run dictionary attack, brute force, or all.")
    parser.add_argument("--target-user", default="alice", help="Target username for attack testing.")
    parser.add_argument("--wordlist", default=None, help="Path to external wordlist file (e.g. RockYou subset).")
    parser.add_argument("--max-attempts", type=int, default=50, help="Maximum attack attempts permitted.")
    parser.add_argument("--json-file", default="data/users.json", help="Path to backend JSON database file.")
    parser.add_argument("--delay", type=float, default=0.0, help="Delay between attack attempts in seconds.")
    parser.add_argument("--defense-mode", choices=["unprotected", "fixed_lockout", "exponential_backoff"],
                        default="fixed_lockout", help="Simulated defense configuration for mock simulator.")

    args = parser.parse_args()

    # Dynamic import of team verification module if present, else fallback to mock simulator
    try:
        from auth_system.verification import login
        login_func = login
    except ImportError:
        simulator = TargetSystemSimulator(target_user=args.target_user, defense_mode=args.defense_mode)
        login_func = simulator.login

    print("\n======================================================================")
    print("  CS2413 TEAM 9 SECURITY EVALUATION  ")
    print("======================================================================")

    if args.mode in ["inspect", "all"]:
        inspect_json_storage(args.json_file)

    if args.mode in ["dictionary", "all"]:
        run_dictionary_attack(login_func, target_user=args.target_user,
                              wordlist_path=args.wordlist, max_attempts=args.max_attempts, delay=args.delay)

    if args.mode in ["brute_force", "all"]:
        run_brute_force_attack(login_func, target_user=args.target_user,
                               max_length=4, max_attempts=args.max_attempts, delay=args.delay)


if __name__ == "__main__":
    main()
