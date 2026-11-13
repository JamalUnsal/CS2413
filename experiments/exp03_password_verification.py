"""Experiment 3 - Password verification and username enumeration.

OWNER: Sandeep Singh.

Procedure
---------
Register a known account, then exercise the login function with:
  * correct username and password;
  * wrong password for an existing account;
  * non-existent username;
  * empty username and empty password;
  * an unusually long password (4096 characters).

Pass criteria (Section 7):
  * correct credentials are accepted and issue a session;
  * every failure is denied without a session;
  * all credential failures return the identical message, so the response does
    not reveal whether the username exists;
  * long/empty input is handled without exceptions.

Run: ``python -m experiments.exp03_password_verification``
"""

from __future__ import annotations

import tempfile
import time
from pathlib import Path

from auth_system.verification import (
    INVALID_CREDENTIALS_MESSAGE,
    dummy_hash_for,
)
from experiments._common import Report, make_runtime, seed, text_table

USERNAME = "alice"
PASSWORD = "Correct-Horse-Battery-9!"
LONG_PASSWORD = "A" * 4096


def _median_seconds(function, repeats: int = 7) -> float:
    samples = []
    for _ in range(repeats):
        started = time.perf_counter()
        function()
        samples.append(time.perf_counter() - started)
    samples.sort()
    return samples[len(samples) // 2]


def main() -> int:
    report = Report(
        "Experiment 3 - Password verification and username enumeration",
        "Protocol: one account, varied credentials; compare messages and timing.",
    )

    with tempfile.TemporaryDirectory() as tmp:
        runtime = make_runtime(Path(tmp))
        try:
            seed(runtime, USERNAME, PASSWORD)

            success = runtime.auth.login(USERNAME, PASSWORD)
            wrong_password = runtime.auth.login(USERNAME, "Definitely-Wrong-1!")
            unknown_user = runtime.auth.login("ghost", "Definitely-Wrong-1!")
            empty_username = runtime.auth.login("", PASSWORD)
            empty_password = runtime.auth.login(USERNAME, "")
            long_password = runtime.auth.login(USERNAME, LONG_PASSWORD)

            report.check("correct credentials accepted", success.success)
            report.check("correct credentials issue a session", bool(success.session_token))
            report.check(
                "session token validates",
                runtime.auth.current_session(success.session_token) is not None,
            )

            for label, result in (
                ("wrong password", wrong_password),
                ("unknown username", unknown_user),
                ("empty username", empty_username),
                ("empty password", empty_password),
                ("4096-character password", long_password),
            ):
                report.check(f"{label}: denied", not result.success)
                report.check(f"{label}: no session issued", result.session_token is None)
                report.check(
                    f"{label}: generic message",
                    result.message == INVALID_CREDENTIALS_MESSAGE,
                    result.message,
                )

            report.check(
                "unknown username and wrong password are indistinguishable",
                wrong_password.message == unknown_user.message,
            )

            print(
                text_table(
                    ("Case", "Accepted", "Message", "Reason (internal only)"),
                    [
                        ("correct credentials", success.success, success.message, success.reason or "-"),
                        ("wrong password", wrong_password.success, wrong_password.message, wrong_password.reason or "-"),
                        ("unknown username", unknown_user.success, unknown_user.message, unknown_user.reason or "-"),
                        ("empty username", empty_username.success, empty_username.message, empty_username.reason or "-"),
                        ("empty password", empty_password.success, empty_password.message, empty_password.reason or "-"),
                        ("4096-char password", long_password.success, long_password.message, long_password.reason or "-"),
                    ],
                )
            )
            print()

            # The dummy hash used for unknown users must have the same bcrypt
            # work factor as real hashes, or response time would leak account
            # existence.  (Checked structurally; local micro-timing is noisy.)
            dummy_hash = dummy_hash_for(runtime.settings.bcrypt_rounds)
            report.check(
                "dummy hash uses the configured bcrypt work factor",
                dummy_hash.split("$")[2] == f"{runtime.settings.bcrypt_rounds:02d}",
                f"cost={dummy_hash.split('$')[2]}, configured={runtime.settings.bcrypt_rounds}",
            )

            unknown_user_time = _median_seconds(
                lambda: runtime.auth.login("nobody-here", "Still-Wrong-2!")
            )
            known_user_time = _median_seconds(
                lambda: runtime.auth.login(USERNAME, "Still-Wrong-2!")
            )
            ratio = known_user_time / unknown_user_time if unknown_user_time else float("inf")
            report.note(
                f"Median failure time: existing user {known_user_time * 1000:.1f} ms, "
                f"unknown user {unknown_user_time * 1000:.1f} ms (ratio {ratio:.2f}) - "
                "informational only; local micro-timing cannot prove absence of a side channel."
            )
            report.note(
                "Timing is measured with a low bcrypt cost for speed; production uses "
                "cost 12 and network noise dominates."
            )
        finally:
            runtime.close()

    return report.finish()


if __name__ == "__main__":
    raise SystemExit(main())
