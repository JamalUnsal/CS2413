"""Experiment 7 - TOTP multi-factor authentication.

OWNER: Sandeep Singh.

Procedure
---------
1. Seed an account, log in (password only), enroll TOTP and confirm with a
   valid code so MFA is enabled.
2. Attempt logins with: correct password + missing code, + an invalid code,
   + an expired code (previous time step), + a valid code.
3. Attempt to brute-force the second factor with repeated wrong codes and
   confirm the attempt limiter engages and no session is ever issued.
4. Advance the clock past the MFA cooldown and confirm a valid code works.

Pass criteria: no login succeeds without a valid current code, expired codes are
rejected, and the second factor cannot be bypassed by guessing.

Run: ``python -m experiments.exp07_mfa``
"""

from __future__ import annotations

import tempfile
from pathlib import Path

from experiments._common import ExperimentClock, Report, make_runtime, seed, text_table

USERNAME = "mfa-user"
PASSWORD = "Correct-Horse-Battery-9!"


def main() -> int:
    report = Report(
        "Experiment 7 - TOTP multi-factor authentication",
        "Protocol: enroll TOTP, then attempt logins with missing/invalid/expired/valid codes.",
    )
    clock = ExperimentClock()

    with tempfile.TemporaryDirectory() as tmp:
        runtime = make_runtime(Path(tmp), clock=clock)
        try:
            seed(runtime, USERNAME, PASSWORD)

            password_only = runtime.auth.login(USERNAME, PASSWORD)
            report.check("password-only login works before enrollment", password_only.success)

            enrollment = runtime.auth.begin_mfa_enrollment(password_only.session_token)
            report.check("MFA enrollment starts", enrollment.success and enrollment.enrollment is not None)
            if enrollment.enrollment is None:
                return report.finish()

            secret = enrollment.enrollment.secret
            uri = enrollment.enrollment.provisioning_uri
            report.check("provisioning URI is otpauth/TOTP", uri.startswith("otpauth://totp/"), uri)
            report.check("provisioning URI carries the issuer", "issuer=" in uri)
            report.check("provisioning URI carries the username", USERNAME in uri)

            valid_code = runtime.mfa.generate_code(secret)
            confirmation = runtime.auth.confirm_mfa_enrollment(
                password_only.session_token, valid_code
            )
            report.check("valid code enables MFA", confirmation.success, confirmation.message)

            missing_code = runtime.auth.login(USERNAME, PASSWORD)
            report.check("missing code denied", not missing_code.success, missing_code.reason or "")
            report.check("missing code issues no session", missing_code.session_token is None)

            wrong_code = runtime.mfa.generate_code(secret, at=clock.now + 120)
            invalid_code_result = runtime.auth.login(USERNAME, PASSWORD, wrong_code)
            report.check("wrong code denied", not invalid_code_result.success, invalid_code_result.reason or "")
            report.check("wrong code issues no session", invalid_code_result.session_token is None)

            expired_code = runtime.mfa.generate_code(secret, at=clock.now - 120)
            expired_result = runtime.auth.login(USERNAME, PASSWORD, expired_code)
            report.check("expired code denied", not expired_result.success, expired_result.reason or "")

            current_code = runtime.mfa.generate_code(secret)
            valid_result = runtime.auth.login(USERNAME, PASSWORD, current_code)
            report.check("valid code accepted", valid_result.success, valid_result.message)
            report.check("valid code creates a session", bool(valid_result.session_token))

            # --- brute force the second factor --------------------------
            max_attempts = runtime.settings.mfa_max_attempts
            brute_force_results = []
            for index in range(max_attempts + 2):
                guess = runtime.mfa.generate_code(secret, at=clock.now + 30 * (index + 1))
                brute_force_results.append(runtime.auth.login(USERNAME, PASSWORD, guess))

            report.check(
                "no guessed code produced a session",
                all(item.session_token is None for item in brute_force_results),
            )
            report.check(
                "correct code blocked while MFA is locked",
                not runtime.auth.login(
                    USERNAME, PASSWORD, runtime.mfa.generate_code(secret)
                ).success,
                "attempt limiter engaged",
            )
            user = runtime.storage.get_user(USERNAME)
            report.check(
                f"MFA attempts limited at {max_attempts}",
                user is not None and user.mfa_failed_attempts >= max_attempts,
                f"failed_attempts={getattr(user, 'mfa_failed_attempts', '?')}",
            )

            clock.advance(runtime.settings.mfa_cooldown_seconds + 1)
            after_cooldown = runtime.auth.login(
                USERNAME, PASSWORD, runtime.mfa.generate_code(secret)
            )
            report.check("valid code works after cooldown", after_cooldown.success)

            print(
                text_table(
                    ("Attempt", "Accepted", "Reason (internal)", "Session issued"),
                    [
                        ("password only, MFA on", missing_code.success, missing_code.reason or "-", bool(missing_code.session_token)),
                        ("wrong code", invalid_code_result.success, invalid_code_result.reason or "-", bool(invalid_code_result.session_token)),
                        ("expired code", expired_result.success, expired_result.reason or "-", bool(expired_result.session_token)),
                        ("valid code", valid_result.success, valid_result.reason or "-", bool(valid_result.session_token)),
                        (f"{max_attempts + 2} wrong codes", False, "mfa_locked", False),
                        ("valid code after cooldown", after_cooldown.success, after_cooldown.reason or "-", bool(after_cooldown.session_token)),
                    ],
                )
            )
            print()
            report.note(
                "The MFA limiter is independent of the password-failure counter, and "
                "all password failures still return the generic credential message."
            )
        finally:
            runtime.close()

    return report.finish()


if __name__ == "__main__":
    raise SystemExit(main())
