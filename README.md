# Team 9 - Password Authentication Prototype

Design, implementation and security evaluation of a Python password
authentication system (CS2413 final project, Team 9).

This repository currently contains the **complete work of Sandeep Singh and
Shalom Olorunfemi**. Every other member's module is present as a documented
placeholder with a ready-to-fill interface, so the team can implement their
parts without restructuring the project.

## Module status

| Area | Owner | Files | Status |
| --- | --- | --- | --- |
| Login menu (terminal + optional Tkinter window), bcrypt verification, generic errors, TOTP MFA, sessions; Experiments 3, 7, 9 | Sandeep Singh | `auth_system/auth.py`, `verification.py`, `mfa.py`, `sessions.py`, `cli.py`, `gui.py`, `experiments/exp03_*`, `exp07_*`, `exp09_*` | Implemented |
| Password change + reset, HMAC integrity, storage interface, JSON + SQLite backends; Experiments 8, 10 | Shalom Olorunfemi | `auth_system/credentials.py`, `storage/*`, `experiments/exp08_*`, `exp10_*` | Implemented |
| Registration, password policy, zxcvbn, bcrypt hashing setup; Experiments 2, 4 | Hazem Alfeky | `auth_system/registration.py`, `policy.py`, `passwords.hash_password` | Placeholder |
| Lockout, rate limiting, exponential backoff, audit log; Experiments 5, 6 | Jamal Unsal | `auth_system/lockout.py`, `audit.py`, `experiments/exp05_*`, `exp06_*` | Placeholder |
| Threat model, documentation, attack scripts, Experiment 1, graphs | Jennifer Cruza | `tools/attack_*.py`, `experiments/exp01_*`, `docs/THREAT_MODEL.md` | Placeholder |

See [`docs/OWNERSHIP.md`](docs/OWNERSHIP.md) for the exact interfaces each
placeholder must satisfy and the suggested order of work.

## Requirements

* Python 3.10 or newer (developed on 3.14, Windows; no platform-specific code).
* Run every command below from this project root (the directory containing
  `auth_system/`).
* Already used by the implemented modules: `bcrypt`, `pyotp`, `pytest`.
* Optional (desktop window only): `qrcode` + `Pillow` render the TOTP
  provisioning URI as a scannable QR code. Without them the window still works
  and shows the secret/URI as text. Tkinter itself ships with Python.
* Only needed by a placeholder owner (install before running their experiment):
  * `zxcvbn` - Hazem (Experiments 2 and 4)
  * `argon2-cffi` - Hazem (Experiment 2 comparison)
  * `matplotlib` - Jennifer (result graphs)

`python -m pip install -r requirements.txt` installs all of them.

## Picking up a placeholder module

1. Read your contract in [`docs/OWNERSHIP.md`](docs/OWNERSHIP.md) - it lists the
   exact method signatures and required behaviour.
2. Fill in the TODO bodies. Keep public signatures unchanged; if you must change
   one, update the calling module and `docs/OWNERSHIP.md` in the same commit.
3. Add tests under `tests/` and run `python -m pytest` - the existing tests must
   stay green.
4. Remove the matching temporary stand-in in `auth_system/runtime.py`
   (`NoLockoutPolicy`, `NullAuditLog`) or delete the scaffolding
   (`auth_system/devtools.py`) once your real module replaces it.
5. Run your experiment script(s); implemented ones exit 0 on success, 1 on a
   failed criterion, and 2 when still a placeholder.

## Quick start

```bash
python -m pip install -r requirements.txt

# Registration is not implemented yet, so seed demo accounts:
python tools/seed_demo_users.py

# Run the login menu (JSON backend):
python -m auth_system

# Or with the SQLite backend:
python -m auth_system --backend sqlite

# Or use the optional desktop window (Tkinter, no extra dependency):
python -m auth_system --gui
```

Demo accounts created by the seeder: `alice`, `bob`, `carol` (passwords are
printed by the script; development only).

The data directory (`data/` by default) is created automatically. Credential
files, the integrity key and audit logs are listed in `.gitignore` - never
commit them.

### What works in the interfaces

Both the terminal menu and the optional desktop window offer the same features:

* Log in with username/password; generic failure message for wrong username and
  wrong password alike.
* Enable TOTP MFA (the provisioning URI can be pasted into an authenticator app,
  or scanned from the optional QR code) and log in with a one-time code.
* Change password (requires the current password; re-applies policy; invalidates
  sessions). Policy is the placeholder, so the interface currently reports that
  dependency until it is implemented.
* Forgot-password reset with a single-use, time-limited token.
* Integrity check.
* Logout invalidates the session token.

The desktop window is a thin view over `AuthService`/`CredentialManager`; it
contains no authentication logic, and the CLI remains the default. It ships with
a dark theme by default (a light theme is one checkbox away) and greets the
signed-in user with "Welcome, &lt;username&gt;". The GUI tests skip automatically
when no display is available.

Registration is intentionally disabled until Hazem implements it.

## Tests

```bash
python -m pytest
```

The suite covers the implemented modules: bcrypt verification (including
>72-byte passwords and malformed hashes), sessions, TOTP, login/MFA flows,
credential change/reset, both storage backends, tamper detection, the CLI, and
the optional Tkinter window (those tests skip automatically without a display).
Tests use a bcrypt cost of 4 for speed; production defaults to 12.

## Experiments

Implemented (Sandeep and Shalom):

```bash
python -m experiments.exp03_password_verification
python -m experiments.exp07_mfa
python -m experiments.exp09_sessions
python -m experiments.exp08_integrity_tampering
python -m experiments.exp10_storage_comparison --users 1000
```

Each script prints a pass/fail table and exits non-zero if a success criterion
fails. Placeholder experiments exit with code 2 and name their owner:

```bash
python -m experiments.exp01_data_inspection   # Jennifer
python -m experiments.exp02_hashing_comparison # Hazem
python -m experiments.exp04_policy_validation  # Hazem
python -m experiments.exp05_online_attack      # Jamal
python -m experiments.exp06_lockout_abuse      # Jamal
```

## Architecture

```
auth_system/
  config.py          tunable settings for every module (shared)
  models.py          UserRecord schema (shared, version 1)
  errors.py          shared exception types
  results.py         OperationResult (shared)
  audit.py           [Jamal] audit interface + temporary null/in-memory sinks
  policy.py          [Hazem] policy + zxcvbn interface (placeholder)
  passwords.py       [Hazem] hash_password (placeholder) + shared prepare_password
  registration.py    [Hazem] registration service (placeholder)
  lockout.py         [Jamal] fixed / exponential backoff (placeholders) + no-op stand-in
  verification.py    [Sandeep] bcrypt verify, dummy-hash padding, generic message
  mfa.py             [Sandeep] TOTP enrollment/verification
  sessions.py        [Sandeep] random tokens, expiry, logout/all invalidation
  auth.py            [Sandeep] login orchestration + MFA enforcement
  credentials.py     [Shalom] change password, reset flow, session invalidation
  storage/
    base.py          [Shalom] StorageBackend + IntegrityReport
    integrity.py     [Shalom] HMAC-SHA256 signer, key file management
    json_backend.py  [Shalom] JSON backend, whole-payload HMAC, atomic writes
    sqlite_backend.py[Shalom] SQLite backend, per-row HMAC + signed manifest
  runtime.py         composition root; point for swapping placeholder services
  cli.py             [Sandeep] terminal menus
  gui.py             [Sandeep] optional Tkinter window (same services as the CLI)
  devtools.py        temporary seeding helper (delete once registration lands)
experiments/         one script per proposal experiment
tools/               demo seeder + attack-script placeholders (Jennifer)
docs/                ownership guide, threat model placeholder
tests/               pytest suite
```

## Security design notes

* **Hashing contract.** bcrypt reads only 72 input bytes; `prepare_password`
  pre-hashes with SHA-256 + base64 so long passphrases are never truncated.
  Sandeep's verifier and Hazem's hasher must keep sharing this helper.
* **Enumeration resistance.** Every credential failure returns
  `Invalid username or password.` Unknown usernames pay the same bcrypt cost via
  a dummy hash at the configured work factor. Internal reasons are never shown.
* **Sessions.** `secrets.token_urlsafe(32)`, absolute expiry, only SHA-256
  fingerprints stored in memory, logout/all-session invalidation, and password
  change/reset invalidates every session.
* **MFA.** TOTP codes are verified with a configurable clock-skew window; wrong
  codes are counted and temporarily lock the second factor.
* **Integrity.** HMAC-SHA256 over canonical JSON. JSON signs the whole user
  payload (detects edits and deletions). SQLite signs every row *and* a
  table-level manifest (detects row edits, insertions and deletions). The key
  lives in a separate file, never in the credential store.
* **Atomic writes.** JSON uses a temp file + `os.replace`; SQLite uses
  transactions and WAL.

## Known limitations (to discuss in the report)

* The integrity key sits next to the data in the prototype; production needs a
  KMS/OS keyring. A local attacker with the key can forge the digest.
* JSON storage rewrites the whole file per write and is not multi-process safe.
* Sessions are in memory, so a restart logs everyone out.
* Reset tokens are printed by the CLI because there is no email delivery.
* Password policy and hashing are not implemented yet (Hazem); lockout/backoff
  and audit persistence are not implemented yet (Jamal).
* The default lockout policy is a documented no-op stand-in so login works
  before Jamal's strategies land.
* Test/experiment seeding bypasses registration (`auth_system/devtools.py`);
  delete it once registration is implemented.
