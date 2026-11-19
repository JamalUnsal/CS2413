"""Experiment 5 - Online brute-force and dictionary attack simulation.

OWNER: Jamal Unsal (assisted by Jennifer Cruza for the attack scripts).

STATUS: IMPLEMENTED

Planned procedure (proposal Section 6, Experiment 5):
  * Run automated attacks against ``AuthService.login`` in three configurations:
    no protection (``NoLockoutPolicy`` stand-in), ``FixedLockoutPolicy`` and
    ``ExponentialBackoffPolicy``.
  * Use both a generated brute-force guess stream and the dictionary wordlist
    from ``tools/attack_dictionary.py``.
  * Measure guesses before blocking, total time and whether the correct
    password was found.
  * Use the audit log as evidence (integrity + lockout events).

The attack scripts themselves live in ``tools/attack_bruteforce.py`` and
``tools/attack_dictionary.py`` (Jennifer's placeholders). This experiment should
drive the same login API and parameterise the lockout policy via
``auth_system.runtime.build_runtime(..., lockout=...)``.

Run: ``python -m experiments.exp05_online_attack``
"""


from __future__ import annotations

import tempfile
import time
from pathlib import Path

from auth_system.audit import AuditEvent, InMemoryAuditLog
from auth_system.config import Settings
from auth_system.lockout import (
    ExponentialBackoffPolicy,
    FixedLockoutPolicy,
    NoLockoutPolicy,
)
from auth_system.runtime import build_runtime
from experiments._common import ExperimentClock, Report, seed, text_table

USERNAME = "alice"
PASSWORD = "Correct-Horse-Battery-9!"

BRUTE_FORCE_GUESSES = [
    "Password123!",
    "Welcome123!",
    "Summer2026!",
]

DICTIONARY_GUESSES = [
    "password",
    "12345678",
    "qwerty123",
]


def run_attack(directory: Path, strategy, guesses: list[str]) -> dict:
    clock = ExperimentClock()
    settings = Settings().with_data_dir(directory)
    settings = Settings(
        **{
            **settings.__dict__,
            "bcrypt_rounds": 4,
            "lockout_threshold": 3,
            "fixed_lockout_seconds": 300,
            "backoff_base_seconds": 30,
            "backoff_max_seconds": 3600,
        }
    )

    audit = InMemoryAuditLog(clock=clock)
    runtime = build_runtime(
        settings,
        audit=audit,
        lockout=strategy,
        clock=clock,
    )

    try:
        seed(runtime, USERNAME, PASSWORD)

        attempts = 0
        started = time.perf_counter()
        final_result = None

        for guess in guesses + [PASSWORD]:
            attempts += 1
            final_result = runtime.auth.login(USERNAME, guess)

            if final_result.success or final_result.reason == "locked_out":
                break

        elapsed = time.perf_counter() - started

        return {
            "attempts": attempts,
            "success": bool(final_result and final_result.success),
            "reason": final_result.reason if final_result else "no_result",
            "elapsed": elapsed,
            "lockouts": len(audit.events_for(AuditEvent.LOCKOUT_TRIGGERED)),
            "blocked": len(audit.events_for(AuditEvent.LOCKOUT_BLOCKED)),
        }
    finally:
        runtime.close()


def main() -> int:
    report = Report(
        "Experiment 5 - Online brute-force and dictionary attack",
        "Three incorrect guesses followed by the correct password.",
    )

    strategies = [
        ("No protection", NoLockoutPolicy()),
        ("Fixed lockout", FixedLockoutPolicy(threshold=3, lockout_seconds=300)),
        ("Exponential backoff", ExponentialBackoffPolicy(
            threshold=3, base_seconds=30, max_seconds=3600
        )),
    ]

    attack_types = [
        ("Brute-force", BRUTE_FORCE_GUESSES),
        ("Dictionary", DICTIONARY_GUESSES),
    ]

    rows = []

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)

        for attack_name, guesses in attack_types:
            for strategy_name, strategy in strategies:
                directory = root / f"{attack_name}_{strategy_name}".replace(" ", "_")
                result = run_attack(directory, strategy, guesses)

                expected_success = strategy_name == "No protection"
                expected_block = strategy_name != "No protection"

                report.check(
                    f"{attack_name}: {strategy_name} outcome",
                    result["success"] == expected_success,
                    f"success={result['success']}, reason={result['reason']}",
                )

                if expected_block:
                    report.check(
                        f"{attack_name}: {strategy_name} blocks attacker",
                        result["reason"] == "locked_out",
                        f"blocked after {result['attempts']} attempts",
                    )

                rows.append((
                    attack_name,
                    strategy_name,
                    result["attempts"],
                    "Yes" if result["success"] else "No",
                    result["reason"],
                    f"{result['elapsed'] * 1000:.2f} ms",
                    result["lockouts"],
                ))

    print(text_table(
        ("Attack", "Protection", "Attempts", "Password found", "Final reason", "Time", "Lockouts"),
        rows,
    ))

    report.note(
        "The correct password was placed after three incorrect guesses. "
        "The protection strategies blocked the fourth attempt while the "
        "no-protection strategy allowed it."
    )
    report.note(
        "This is a controlled local simulation, not an attack against a real account."
    )

    return report.finish()


if __name__ == "__main__":
    raise SystemExit(main())
