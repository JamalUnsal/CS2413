#!/usr/bin/env python3
"""
Experiment 1 Runner (exp01_data_inspection.py)
CS2413 - Team 9 Password Authentication System Security Design
OWNER: Jennifer Cruza

Description:
Official experiment runner for Experiment 1 (Credential Data Inspection).
Verifies backend credential storage confidentiality:
1. Ensures 0 plaintext passwords exist in storage.
2. Ensures unique per-user salts prevent hash collisions across identical passwords.
"""

from __future__ import annotations
import argparse
import json
import os
import sys
from pathlib import Path
from typing import Dict, Any

# Ensure project root is in Python path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

# Flexible import from tools/attack_simulator
try:
    from tools.attack_simulator import inspect_json_storage
except ImportError:
    try:
        from attack_simulator import inspect_json_storage
    except ImportError:
        def inspect_json_storage(json_path: str = "data/users.json") -> Dict[str, Any]:
            if not os.path.exists(json_path):
                return {"total_users": 0, "plaintext_found": 0, "salt_duplications": 0, "passed": False}
            with open(json_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            users = data.get("users", data if isinstance(data, dict) else {})
            plaintext = 0
            hashes = set()
            dup_hashes = 0
            for u, rec in users.items():
                if isinstance(rec, dict):
                    h = str(rec.get("password_hash", rec.get("hash", "")))
                    if not (h.startswith("$") or len(h) >= 32):
                        plaintext += 1
                    if h in hashes:
                        dup_hashes += 1
                    hashes.add(h)
            return {
                "total_users": len(users),
                "plaintext_found": plaintext,
                "salt_duplications": dup_hashes,
                "passed": (plaintext == 0 and dup_hashes == 0)
            }


def run_experiment_1(json_path: str = "data/users.json") -> Dict[str, Any]:
    """
    Executes Experiment 1 evaluation and returns structured results dictionary
    suitable for pytest assertions and report metrics generation.
    """
    print(f"\n[Experiment 01] Launching Data Inspection on database: '{json_path}'")
    results = inspect_json_storage(json_path)
    
    # Assertions for integration test runners
    assert results["plaintext_found"] == 0, f"FAILED: Found {results['plaintext_found']} plaintext passwords!"
    assert results["salt_duplications"] == 0, f"FAILED: Found {results['salt_duplications']} duplicate hash collisions!"
    
    return results


def test_exp01_confidentiality():
    """
    Pytest compatible unit test function for CI/CD integration.
    """
    mock_db_path = str(PROJECT_ROOT / "tests" / "test_users_mock.json")
    os.makedirs(os.path.dirname(mock_db_path), exist_ok=True)
    
    mock_data = {
        "users": {
            "test_user1": {
                "username": "test_user1",
                "password_hash": "$2b$12$e8N8...KzO1234567890abcdefghijklmnopqrst",
                "salt": "salt_val_1"
            },
            "test_user2": {
                "username": "test_user2",
                "password_hash": "$2b$12$x9M7...LpP9876543210zyxwvutsrqponmlkj",
                "salt": "salt_val_2"
            }
        }
    }
    with open(mock_db_path, "w", encoding="utf-8") as f:
        json.dump(mock_data, f)
        
    try:
        results = run_experiment_1(mock_db_path)
        assert results["passed"] is True
    finally:
        if os.path.exists(mock_db_path):
            os.remove(mock_db_path)


def main():
    parser = argparse.ArgumentParser(description="Experiment 1 Runner (CS2413 Team 9 - Jennifer Cruza)")
    parser.add_argument("--json-file", default="data/users.json",
                        help="Path to backend JSON credential database file.")
    args = parser.parse_args()

    results = run_experiment_1(args.json_file)
    sys.exit(0 if results["passed"] else 1)


if __name__ == "__main__":
    main()
