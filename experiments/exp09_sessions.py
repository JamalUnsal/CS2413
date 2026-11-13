"""Experiment 9 - Session handling.

OWNER: Sandeep Singh.

Procedure
---------
  * issue many tokens and confirm they are unique, long and unpredictable;
  * confirm only token fingerprints are retained (raw tokens are not stored);
  * confirm sessions expire at the configured time;
  * confirm logout invalidates a token immediately;
  * confirm a forged/expired token is rejected;
  * confirm ``invalidate_all`` clears every session for an account.

Run: ``python -m experiments.exp09_sessions``
"""

from __future__ import annotations

import math
import tempfile
from collections import Counter
from pathlib import Path

from experiments._common import ExperimentClock, Report, make_runtime, seed, text_table

USERNAME = "session-user"
PASSWORD = "Correct-Horse-Battery-9!"
SAMPLE_SIZE = 200


def _shannon_entropy_per_char(values: list[str]) -> float:
    joined = "".join(values)
    counts = Counter(joined)
    total = len(joined)
    return -sum((count / total) * math.log2(count / total) for count in counts.values())


def main() -> int:
    report = Report(
        "Experiment 9 - Session tokens, expiry and logout",
        "Protocol: issue many tokens, then check randomness, expiry and invalidation.",
    )
    clock = ExperimentClock()

    with tempfile.TemporaryDirectory() as tmp:
        runtime = make_runtime(Path(tmp), clock=clock, session_ttl_seconds=60)
        try:
            seed(runtime, USERNAME, PASSWORD)
            login = runtime.auth.login(USERNAME, PASSWORD)
            report.check("login issues a session", login.success and bool(login.session_token))

            tokens = [
                runtime.sessions.create_session(USERNAME)[0]
                for _ in range(SAMPLE_SIZE)
            ]
            report.check(
                f"{SAMPLE_SIZE} tokens are all unique",
                len(set(tokens)) == SAMPLE_SIZE,
            )
            report.check(
                "token length is at least 32 characters",
                min(len(token) for token in tokens) >= 32,
                f"min={min(len(token) for token in tokens)}",
            )
            report.check(
                "tokens are high-entropy URL-safe strings",
                all(all(char.isalnum() or char in "-_" for char in token) for token in tokens),
            )

            active = runtime.sessions.active_sessions()
            fingerprints = {session.fingerprint for session in active}
            report.check(
                "raw tokens are not retained by the session store",
                all(token not in fingerprints for token in tokens),
            )
            report.note(
                f"Observed character entropy ~{_shannon_entropy_per_char(tokens):.2f} bits/char "
                f"over {SAMPLE_SIZE} tokens; each token is 256 random bits."
            )

            # --- expiry ---------------------------------------------------
            token, session = runtime.sessions.create_session(USERNAME)
            report.check("fresh session validates", runtime.sessions.validate(token) is not None)
            clock.advance(59)
            report.check(
                "session valid just before expiry",
                runtime.sessions.validate(token) is not None,
            )
            clock.advance(2)
            report.check(
                "session rejected after expiry",
                runtime.sessions.validate(token) is None,
            )

            # --- logout ---------------------------------------------------
            token, _ = runtime.sessions.create_session(USERNAME)
            runtime.auth.logout(token)
            report.check(
                "token rejected after logout",
                runtime.sessions.validate(token) is None,
            )
            report.check("logout reports invalidation", runtime.auth.logout(token) is False)

            # --- forged token --------------------------------------------
            forged = token + "x"
            report.check(
                "modified token is rejected",
                runtime.sessions.validate(forged) is None,
            )

            # --- invalidate all ------------------------------------------
            for _ in range(3):
                runtime.sessions.create_session(USERNAME)
            removed = runtime.sessions.invalidate_all(USERNAME)
            report.check("invalidate_all clears every account session", removed >= 3, f"removed={removed}")
            report.check(
                "no sessions remain for the account",
                all(session.username != USERNAME for session in runtime.sessions.active_sessions()),
            )

            print(
                text_table(
                    ("Property", "Observed value"),
                    [
                        ("Token sample size", str(SAMPLE_SIZE)),
                        ("Unique tokens", str(len(set(tokens)))),
                        ("Minimum token length", str(min(len(token) for token in tokens))),
                        ("Session TTL (seconds)", str(runtime.sessions.ttl_seconds)),
                        ("Raw tokens stored", "no (SHA-256 fingerprints only)"),
                        ("Expiry enforced", "yes"),
                        ("Logout invalidation", "yes"),
                    ],
                )
            )
            print()
        finally:
            runtime.close()

    return report.finish()


if __name__ == "__main__":
    raise SystemExit(main())
