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

#seclists most common passwords URL (for dictionary attack)
WORDLIST_URL = "https://raw.githubusercontent.com/danielmiessler/SecLists/refs/heads/master/Passwords/Common-Credentials/10k-most-common.txt"


# ensure project root is in Python path for clean imports across folders
SCRIPT_DIR = Path(__file__).resolve().parent
REPO_ROOT = SCRIPT_DIR.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from auth_system.runtime import build_runtime
from auth_system.config import Settings

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
    adapter connecting the attack simulator to the real auth system
    """

    def __init__(self, auth_service):
        self.auth = auth_service

    def login(self, username: str, password: str):
        return self.auth.login(
            username=username,
            password=password
        )

def main():
    parser = argparse.ArgumentParser(
        description="CS2413 Team 9 Master Security Evaluation Suite"
    )

    parser.add_argument(
        "--mode",
        choices=["inspect", "dictionary", "brute_force", "all"],
        default="all"
    )

    parser.add_argument("--target-user", default="alice")
    parser.add_argument("--wordlist", default=None)
    parser.add_argument("--url", default= WORDLIST_URL)
    parser.add_argument("--max-attempts", type=int, default=20)
    parser.add_argument("--json-file", default="data/users.json")

    args = parser.parse_args()

    print("\n" + "=" * 70)
    print("  ATTACK SIMULATOR - REAL AUTHENTICATION")
    print("=" * 70)

    # use the project's data directory.
    settings = Settings(
        data_dir=REPO_ROOT / "data"
    )

    print(f"[*] User database: {settings.users_path}")
    print(f"[*] Integrity key: {settings.integrity_key_path}")

    runtime = None
    
    
    try:
        from auth_system.lockout import NoLockoutPolicy

        # init real auth system
        runtime = build_runtime(
            settings=settings,
            backend="json",
            #lockout =NoLockoutPolicy()
        )

        simulator = TargetSystemSimulator(runtime.auth)

        print("[+] Real authentication system connected!")

        if args.mode in ["inspect", "all"]:
            inspect_json_storage(
                str(settings.users_path)
            )

        if args.mode in ["dictionary", "all"]:
            run_dictionary_attack(
                simulator.login,
                target_user=args.target_user,
                wordlist_path=args.wordlist,
                remote_url = args.url,
                max_attempts=args.max_attempts
            )

        if args.mode in ["brute_force", "all"]:
            run_brute_force_attack(
                simulator.login,
                target_user=args.target_user,
                max_attempts=args.max_attempts
            )

    except Exception as error:
        print(f"\n[!] Simulator error: {error}")
        raise

    finally:
        if runtime is not None:
            runtime.close()
            print("\n[*] Authentication runtime closed.")


if __name__ == "__main__":
    main()