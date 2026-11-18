#!/usr/bin/env python3
"""
Dictionary Attack Tool

OWNER: Jennifer Cruza
"""

import argparse
import os
import sys
import time
import urllib.request
from pathlib import Path
from typing import Dict, Any, List, Optional
import ssl 
import urllib.request

#seclists most common passwords URL
DEFAULT_WORDLIST_URL = "https://raw.githubusercontent.com/danielmiessler/SecLists/refs/heads/master/Passwords/Common-Credentials/10k-most-common.txt"

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

DEFAULT_OFFLINE_WORDLIST = [
    "123456", "password", "123456789", "12345678", "12345",
    "qwerty", "password123", "dragon", "admin", "welcome",
    "P@ssword123!", "Secur3P@ss2026!", "RockYouSubset2026", "alice123"
]

def fetch_remote_wordlist(url: str, timeout: float = 3.0) -> List[str]:
    """Dynamically fetches candidate passwords from a public dataset at runtime."""
    if not url:
        return []
    try:
        # create unverified SSL context to bypass missing certs (for mac)
        ssl_ctx = ssl._create_unverified_context()

        req = urllib.request.Request(
            url, 
            headers={"User-Agent": "CS2413 Evaluation Test Harness"}
        )
        with urllib.request.urlopen(req, timeout=timeout, context=ssl_ctx) as response:
            content = response.read().decode('utf-8', errors='ignore')
            lines = [line.strip() for line in content.splitlines() if line.strip()]
            if lines:
                print(f"[*] Successfully fetched {len(lines)} candidates from remote wordlist.")
                return lines
    except Exception as e:
        print(f"[*] Remote wordlist fetch skipped/failed ({e}). Falling back to embedded list.")
    return []

def get_wordlist(wordlist_path: Optional[str] = None, remote_url: Optional[str] = None) -> List[str]:
    """Resolves wordlist from local file, remote URL, or embedded fallback."""
    if wordlist_path and os.path.exists(wordlist_path):
        print(f"[*] Reading local wordlist file: {wordlist_path}")
        with open(wordlist_path, "r", encoding="utf-8", errors="ignore") as f:
            candidates = [line.strip() for line in f if line.strip()]
            if candidates:
                return candidates

    if remote_url:
        print("[*] Attempting dynamic wordlist fetch from public URL...")
        remote_candidates = fetch_remote_wordlist(remote_url)
        if remote_candidates:
            return remote_candidates

    print("[*] Using embedded offline candidate wordlist.")
    return DEFAULT_OFFLINE_WORDLIST

def run_dictionary_attack(
    login_func,
    target_user: str = "alice",
    wordlist_path: Optional[str] = None,
    remote_url: Optional[str] = None,
    max_attempts: int = 50,
    delay: float = 0.0
) -> Dict[str, Any]:
    print("\n" + "="*70)
    print(f"  EXPERIMENT 5: DICTIONARY EVALUATION (Target: '{target_user}')")
    print("="*70)

    candidates = get_wordlist(wordlist_path=wordlist_path, remote_url=remote_url)
    candidates = candidates[:max_attempts]
    print(f"[*] Starting test with {len(candidates)} candidate passwords...\n")

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

        success = False
        message = ""
        locked = False

        if hasattr(res, "success"):
            success = bool(getattr(res, "success"))
            reason = getattr(res, "reason", "")
            message = getattr(res, "message", reason)
            locked = (reason == "locked_out" or "locked" in str(message).lower())
        elif isinstance(res, dict):
            success = res.get("success", False)
            message = res.get("message", res.get("reason", ""))
            locked = res.get("locked", res.get("reason") == "locked_out" or "locked" in str(message).lower())
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
            print(f"  [Attempt {attempts:03d}] Candidate: '{candidate:<16}' -> RESULT: SUCCESS! Match found.")
            break

        print(f"  [Attempt {attempts:03d}] Candidate: '{candidate:<16}' -> RESULT: REJECTED ({message})")

    total_time = time.time() - start_time
    avg_latency = (sum(latencies) / len(latencies)) if latencies else 0.0

    print("-" * 70)
    print("DICTIONARY EVALUATION SUMMARY:")
    print(f"  • Target Username       : {target_user}")
    print(f"  • Total Attempts Made   : {attempts}")
    print(f"  • Elapsed Time          : {total_time:.4f} seconds")
    print(f"  • Average Latency/Req   : {avg_latency * 1000:.2f} ms")
    print(f"  • Account Locked Out    : {'YES (Defense Working)' if lockout_occurred else 'NO'}")
    print(f"  • Test Result           : {'MATCH FOUND' if successful_password else 'BLOCKED / UNSUCCESSFUL'}")
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
    parser = argparse.ArgumentParser(description="Dictionary Test Harness (CS2413 Team 9 - Jennifer Cruza)")
    parser.add_argument("--target-user", default="alice", help="Target username for test.")
    parser.add_argument("--wordlist", default=None, help="Path to local wordlist file.")
    parser.add_argument("--url", default=DEFAULT_WORDLIST_URL, help="Optional remote URL to download wordlist")
    parser.add_argument("--max-attempts", type=int, default=50, help="Max candidates to test")
    parser.add_argument("--delay", type=float, default=0.0, help="Delay between attempts in seconds")
    args = parser.parse_args()

    from auth_system.runtime import build_runtime
    from auth_system.config import Settings

    settings = Settings(data_dir=PROJECT_ROOT / "data")

    runtime = build_runtime(
        settings=settings,
        backend="json"
    )

    login_func = runtime.auth.login

    try:
        results = run_dictionary_attack(
            login_func,
            target_user=args.target_user,
            wordlist_path=args.wordlist,
            remote_url=args.url,
            max_attempts=args.max_attempts
        )
    finally:
        runtime.close()

if __name__ == "__main__":
    main()
