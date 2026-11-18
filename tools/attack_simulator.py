#!/usr/bin/env python3
"""
Attack Simulation & Master Suite Orchestrator

OWNER: Jennifer Cruza

Description

Test simulator orchestrating following security evaluations:
1. Experiment 1: JSON Credential Data Inspection (from experiments/exp01_data_inspection.py)
2. Experiment 5: Automated Dictionary Attack (from tools/attack_dictionary.py)
3. Experiment 5: Automated Brute-Force Attack (from tools/attack_bruteforce.py)
"""

from __future__ import annotations
import argparse
import sys
import time
from pathlib import Path
from typing import Dict, Any

# ensure project root is in Python path for clean imports across folders
SCRIPT_DIR = Path(__file__).resolve().parent
REPO_ROOT = SCRIPT_DIR.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

# import Experiment 1
try:
    from experiments.exp01_data_inspection import inspect_json_storage
except ImportError:
    try:
        from exp01_data_inspection import inspect_json_storage
    except ImportError:
        def inspect_json_storage(json_path: str = "data/users.json") -> Dict[str, Any]:
            print(f"[!] Warning: exp01_data_inspection module not found. Path: {json_path}")
            return {"passed": False, "plaintext_found": 0, "salt_duplications": 0}

# import Experiment 5 attack modules
try:
    from tools.attack_dictionary import run_dictionary_attack
except ImportError:
    try:
        from attack_dictionary import run_dictionary_attack
    except ImportError:
        def run_dictionary_attack(*args, **kwargs) -> Dict[str, Any]:
            print("[!] Warning: attack_dictionary module not found.")
            return {"success": False}

try:
    from tools.attack_bruteforce import run_brute_force_attack
except ImportError:
    try:
        from attack_bruteforce import run_brute_force_attack
    except ImportError:
        def run_brute_force_attack(*args, **kwargs) -> Dict[str, Any]:
            print("[!] Warning: attack_bruteforce module not found.")
            return {"success": False}


class TargetSystemSimulator:
    """
    Mock implementation of the team's authentication backend.
    (used for standalone attack script testing prior to team module integration)
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
        Simulates login verification endpoint.
        """
        start_time = time.time()
        now = start_time

        # check if currently locked out
        if now < self.locked_until:
            return {
                "success": False,
                "message": "Account locked due to multiple failed attempts.",
                "locked": True,
                "latency_sec": time.time() - start_time
            }

        # apply exponential backoff delay if enabled
        if self.defense_mode == "exponential_backoff" and self.failed_attempts > 0:
            delay = self.backoff_delay * (2 ** (self.failed_attempts - 1))
            time.sleep(min(delay, 2.0))

        # verify credentials
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


def main():
    parser = argparse.ArgumentParser(description="CS2413 Team 9 Master Security Evaluation Suite (Jennifer Cruza)")
    parser.add_argument("--mode", choices=["inspect", "dictionary", "brute_force", "all"], default="all",
                        help="Execution mode: inspect JSON, run dictionary attack, brute force, or all.")
    parser.add_argument("--target-user", default="alice", help="Target username for attack testing.")
    parser.add_argument("--wordlist", default=None, help="Path to external wordlist file (e.g. RockYou subset).")
    parser.add_argument("--max-attempts", type=int, default=20, help="Maximum attack attempts permitted.")
    parser.add_argument("--json-file", default="data/users.json", help="Path to database JSON file.")
    parser.add_argument("--defense-mode", choices=["unprotected", "fixed_lockout", "exponential_backoff"],
                        default="fixed_lockout", help="Simulated defense configuration.")

    args = parser.parse_args()

    simulator = TargetSystemSimulator(target_user=args.target_user, defense_mode=args.defense_mode)

    print("\n======================================================================")
    print("  ATTACK SIMULATOR - SECURITY EVALUATION ")
    print("======================================================================")

    if args.mode in ["inspect", "all"]:
        inspect_json_storage(args.json_file)

    if args.mode in ["dictionary", "all"]:
        run_dictionary_attack(simulator.login, target_user=args.target_user,
                             max_attempts=args.max_attempts)

    if args.mode in ["brute_force", "all"]:
        run_brute_force_attack(simulator.login, target_user=args.target_user, max_attempts=10)


if __name__ == "__main__":
    main()
