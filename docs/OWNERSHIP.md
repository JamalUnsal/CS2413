# Ownership and handoff guide

This project was scaffolded so that each member owns a small, independent
surface with a stable interface. The implemented modules never import a
placeholder's internals - only its public contract - so filling a placeholder
does not require changing anyone else's code.

## Status summary

| Owner | Module(s) | Status | Experiments |
| --- | --- | --- | --- |
| Sandeep Singh | `auth_system/verification.py`, `mfa.py`, `sessions.py`, `auth.py`, `cli.py`, `gui.py` | Implemented + tested | 3, 7, 9 |
| Shalom Olorunfemi | `auth_system/credentials.py`, `auth_system/storage/*` | Implemented + tested | 8, 10 |
| Hazem Alfeky | `auth_system/passwords.py` (`hash_password`), `policy.py`, `registration.py` | Placeholder | 2, 4 |
| Jamal Unsal | `auth_system/lockout.py`, `auth_system/audit.py` | Placeholder (temporary stand-ins exist) | 5, 6 |
| Jennifer Cruza | `tools/attack_bruteforce.py`, `tools/attack_dictionary.py`, `experiments/exp01_*`, `docs/THREAT_MODEL.md` | Placeholder | 1 |

Shared/phase-1 files implemented here: `config.py`, `models.py`, `errors.py`,
`results.py`, `runtime.py`, `devtools.py` (temporary).

## Implemented surfaces (do not break these contracts)

### Sandeep - login, verification, MFA, sessions

* `verification.verify_password(stored_hash, password) -> bool` never raises.
* `verification.INVALID_CREDENTIALS_MESSAGE` is the only credential-failure text.
* `AuthService.login(username, password, totp_code=None) -> LoginResult`
  * `LoginResult.message` is user-facing and generic;
  * `LoginResult.reason` is internal (`bad_password`, `unknown_user`,
    `locked_out`, `mfa_required`, `mfa_failed`, `mfa_locked`);
  * on success `session_token` is set exactly once.
* `SessionManager` stores only SHA-256 fingerprints and enforces absolute expiry.
* `MfaService` uses `Settings.mfa_*`; codes are normalised and window-checked.
* `cli.py` is the reference interface; `gui.py` is an optional Tkinter view over
  the same services (no authentication logic, tests skip without a display). It
  defaults to a dark theme with a light toggle, greets the signed-in user, and
  renders the TOTP provisioning URI as a QR code only when the optional
  `qrcode`/`Pillow` packages are installed.
* Unit tests: `tests/test_verification.py`, `test_sessions.py`, `test_mfa.py`,
  `test_auth_login.py`, `test_cli.py`, `test_gui.py`.

### Shalom - credential updates, integrity, storage

* `StorageBackend`: `get_user`, `save_user`, `list_users`, `delete_user`,
  `verify_integrity`, `close`. `create_storage("json"|"sqlite", settings)`
  builds either backend.
* `JsonStorage` signs the whole payload; `SqliteStorage` signs each row and a
  table manifest; both raise `IntegrityError` instead of trusting bad data.
* `CredentialManager.change_password(username, old_password, new_password,
  session_token=None)` verifies the old password, checks reuse, applies
  `policy.validate_password`, hashes with the injected hasher, and invalidates
  all sessions.
* `request_password_reset(username)` always returns the same message; the token
  (when issued) is single-use and expires.
* Unit tests: `tests/test_storage_integrity.py`, `test_credentials.py`.

## Placeholder contracts

### Hazem Alfeky

**`passwords.hash_password(password, rounds=12) -> str`**
* Use `prepare_password(password)` (already implemented) then
  `bcrypt.hashpw(..., bcrypt.gensalt(rounds=rounds)).decode()`.
* Validate `4 <= rounds <= 31`.
* Keep the bcrypt string (salt + cost are embedded); leave `UserRecord.salt` as
  `None`.

**`policy.PasswordPolicy.validate_password(username, password) -> PolicyResult`**
* Enforce `Settings.password_min_length` (12), `password_max_length` (128),
  upper/lower/digit/special, blocklist (`Settings.blocklist_path`), no username
  substring, and zxcvbn score >= `Settings.password_min_strength` (3).
* Return every reason in `PolicyResult.reasons`; never raise for a weak password.
* Implement `load_blocklist()` with caching and `strength()` for the prompt.

**`registration.RegistrationService.register(username, password) -> RegistrationResult`**
* Strip/validate username, reject duplicates, run the policy, hash with the
  configured rounds, save a `UserRecord` with timestamps from `self._clock`,
  audit `REGISTRATION`, and never log the password.
* When done: wire nothing else - the CLI and `CredentialManager` already call
  these interfaces. Delete `auth_system/devtools.py` and update
  `tools/seed_demo_users.py` to use registration (or remove the seeder).

### Jamal Unsal

**`lockout.LockoutPolicy`**
* `check(user, now) -> LockoutDecision`: `allowed=False` + `retry_after` while
  locked.
* `register_failure(user, now) -> LockoutDecision`: mutate
  `failed_attempts`/`lockout_until`, persist happens in `AuthService`.
* `reset(user, now)`: clear both fields.
* Implement `FixedLockoutPolicy` (fixed window after N failures) and
  `ExponentialBackoffPolicy` (doubling delay, capped, timed unlock only).
* In `auth_system/runtime.py`, replace `NoLockoutPolicy()` with the chosen
  strategy (or read it from configuration).

**`audit.AuditLog.record(event, username=None, details=None)`**
* Append one timestamped line/JSON object per event. Use `AuditEvent` names.
* Never store passwords, OTP codes, session tokens or reset tokens.
* Keep `record` non-throwing (write failures go to stderr).
* In `runtime.build_runtime`, replace `NullAuditLog()` with
  `AuditLog(settings.audit_log_path)` (or a factory that creates the file).
* The rest of the system already calls the right events; tests assert on
  `InMemoryAuditLog` so they keep working either way.

### Jennifer Cruza

* `docs/THREAT_MODEL.md`: expand the outline into the T1-T9 table from the
  approved proposal, with CIA mapping and control references.
* `tools/attack_bruteforce.py` / `attack_dictionary.py`: fill the planned
  argparse contract; call `AuthService.login` against synthetic accounts; stop
  on `reason == "locked_out"`; summarise guesses, time and audit events.
* `experiments/exp01_data_inspection.py`: seed two users with the same password,
  print the raw JSON (no plaintext, different hashes) and record the pass/fail.
* Results consolidation/graphs: collect outputs from the experiment scripts;
  `matplotlib` is listed in `requirements.txt`.

## Integration checklist (when a placeholder lands)

1. Run `python -m pytest` (all tests must stay green).
2. Run the affected experiment script.
3. If you changed a public interface, update the calling module and this guide.
4. Remove the corresponding stand-in (`NoLockoutPolicy`, `NullAuditLog`,
   `devtools.py`) and its mentions in the README.
5. Never weaken the failure-message contract in `verification.py`.

## Testing and experiment commands

```bash
python -m pytest
python -m experiments.exp03_password_verification
python -m experiments.exp07_mfa
python -m experiments.exp08_integrity_tampering
python -m experiments.exp09_sessions
python -m experiments.exp10_storage_comparison --users 1000
```

Placeholder experiments return exit code 2 and state their owner.
