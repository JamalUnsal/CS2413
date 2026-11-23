"""Experiment 6 - Lockout abuse / availability test.

OWNER: Jamal Unsal.

STATUS: IMPLEMENTED

"""


from __future__ import annotations

import tempfile
from pathlib import Path

from auth_system.audit import AuditEvent, InMemoryAuditLog
from auth_system.config import Settings
from auth_system.lockout import (
    ExponentialBackoffPolicy,
    FixedLockoutPolicy,
)
from auth_system.runtime import build_runtime
from experiments._common import ExperimentClock, Report, seed, text_table

USERNAME = "alice"
PASSWORD = "Correct-Horse-Battery-9!"
WRONG_PASSWORD = "Incorrect-Password-123!"


def run_test(directory: Path, strategy) -> dict:
    clock = ExperimentClock()
    settings = Settings().with_data_dir(directory)
    settings = Settings(
        **{
            **settings.__dict__,
            "bcrypt_rounds": 4,
            "lockout_threshold": 3,
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

        # First series of failed attempts triggers the first lockout.
        for _ in range(3):
            runtime.auth.login(USERNAME, WRONG_PASSWORD)

        user = runtime.storage.get_user(USERNAME)
        first_lock_seconds = user.lockout_until - clock()

        # A legitimate user is blocked during the lockout.
        blocked_first = runtime.auth.login(USERNAME, PASSWORD)

        # Advance simulated time until the first lockout expires.
        clock.advance(first_lock_seconds + 1)

        # Another failed attempt triggers a second lockout.
        second_failure = runtime.auth.login(USERNAME, WRONG_PASSWORD)
        user = runtime.storage.get_user(USERNAME)
        second_lock_seconds = user.lockout_until - clock()

        # The legitimate user is blocked again.
        blocked_second = runtime.auth.login(USERNAME, PASSWORD)

        # Advance time until the second lockout expires.
        clock.advance(second_lock_seconds + 1)
        recovered = runtime.auth.login(USERNAME, PASSWORD)

        return {
            "first_lock": first_lock_seconds,
            "second_lock": second_lock_seconds,
            "blocked_first": blocked_first.reason == "locked_out",
            "blocked_second": blocked_second.reason == "locked_out",
            "recovered": recovered.success,
            "lockout_events": len(audit.events_for(AuditEvent.LOCKOUT_TRIGGERED)),
        }
    finally:
        runtime.close()


def main() -> int:
    report = Report(
        "Experiment 6 - Lockout abuse and account availability",
        "Simulated repeated attacks against a legitimate user's account.",
    )

    strategies = [
        ("Fixed lockout", FixedLockoutPolicy(
            threshold=3, lockout_seconds=300
        )),
        ("Exponential backoff", ExponentialBackoffPolicy(
            threshold=3, base_seconds=30, max_seconds=3600
        )),
    ]

    rows = []

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)

        for name, strategy in strategies:
            result = run_test(root / name.replace(" ", "_"), strategy)

            report.check(
                f"{name}: first legitimate login blocked",
                result["blocked_first"],
            )
            report.check(
                f"{name}: second legitimate login blocked",
                result["blocked_second"],
            )
            report.check(
                f"{name}: login works after lockout expires",
                result["recovered"],
            )
            report.check(
                f"{name}: two lockouts recorded",
                result["lockout_events"] == 2,
                f"events={result['lockout_events']}",
            )

            rows.append((
                name,
                f"{result['first_lock']:.0f} seconds",
                f"{result['second_lock']:.0f} seconds",
                "Yes" if result["blocked_first"] else "No",
                "Yes" if result["recovered"] else "No",
            ))

    print(text_table(
        ("Strategy", "First lockout", "Second lockout",
         "Legitimate user blocked", "Recovered"),
        rows,
    ))

    report.note(
        "Fixed lockout uses the same delay for each lockout. "
        "Exponential backoff doubles the delay after each additional failure."
    )
    report.note(
        "Lockouts are temporary. A legitimate user can log in after the "
        "lockout period expires, provided the correct password is supplied."
    )
    report.note(
        "This demonstrates the availability trade-off: an attacker can "
        "temporarily prevent a legitimate user from accessing their account."
    )

    return report.finish()


if __name__ == "__main__":
    raise SystemExit(main())
