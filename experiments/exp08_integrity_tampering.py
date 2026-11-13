"""Experiment 8 - Integrity and tampering detection.

OWNER: Shalom Olorunfemi.

Procedure
---------
For each tampering scenario, build a fresh JSON store, record the baseline
integrity result, apply the edit directly to the file (bypassing the storage
API), then:
  * run the offline integrity inspector;
  * attempt to open the store (must raise ``IntegrityError``);
  * confirm an ``integrity_failure`` event reached the audit sink;
  * confirm the failed load did not rewrite or "repair" the file.

Scenarios: changed password hash, reset failed-attempt counter, removed
lockout, deleted user record, and a mismatched (wrong) HMAC key.

Run: ``python -m experiments.exp08_integrity_tampering``
"""

from __future__ import annotations

import json
import tempfile
from pathlib import Path
from typing import Callable

from auth_system.audit import AuditEvent, InMemoryAuditLog
from auth_system.config import Settings
from auth_system.errors import IntegrityError
from auth_system.runtime import build_runtime
from auth_system.storage import JsonStorage, inspect_json_storage
from auth_system.storage.integrity import IntegritySigner
from auth_system import devtools
from experiments._common import ExperimentClock, Report, make_settings, text_table


def _baseline(directory: Path, audit: InMemoryAuditLog, clock: ExperimentClock) -> Settings:
    settings = make_settings(directory)
    runtime = build_runtime(settings, audit=audit, clock=clock)
    try:
        devtools.seed_user(
            runtime.storage,
            "alice",
            "Correct-Horse-Battery-9!",
            rounds=settings.bcrypt_rounds,
            clock=clock,
            failed_attempts=5,
            lockout_until=clock() + 300,
        )
        devtools.seed_user(
            runtime.storage,
            "bob",
            "Other-Password-4!",
            rounds=settings.bcrypt_rounds,
            clock=clock,
        )
    finally:
        runtime.close()
    return settings


def _mutate_file(path: Path, mutate: Callable[[dict], None]) -> None:
    document = json.loads(path.read_text(encoding="utf-8"))
    mutate(document["users"])
    path.write_text(
        json.dumps(document, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def _tamper_hash(users: dict) -> None:
    users["alice"]["password_hash"] = "$2b$12$" + "0" * 53


def _tamper_counter(users: dict) -> None:
    users["alice"]["failed_attempts"] = 0


def _tamper_lockout(users: dict) -> None:
    users["alice"]["lockout_until"] = None


def _tamper_delete(users: dict) -> None:
    del users["bob"]


def main() -> int:
    report = Report(
        "Experiment 8 - HMAC integrity and tampering detection",
        "Protocol: edit data/users.json directly, then inspect and try to load it.",
    )
    clock = ExperimentClock()

    scenarios = (
        ("changed password hash", _tamper_hash),
        ("reset failed-attempt counter", _tamper_counter),
        ("removed lockout", _tamper_lockout),
        ("deleted user record", _tamper_delete),
    )
    rows: list[tuple[str, str, str, str]] = []

    with tempfile.TemporaryDirectory() as tmp:
        for index, (label, mutate) in enumerate(scenarios):
            directory = Path(tmp) / f"scenario_{index}"
            audit = InMemoryAuditLog(clock=clock)
            settings = _baseline(directory, audit, clock)

            baseline = inspect_json_storage(settings.users_path, settings.integrity_key_path)
            report.check(f"{label}: baseline file is valid", baseline.ok, baseline.describe())

            _mutate_file(settings.users_path, mutate)
            before_load = settings.users_path.read_bytes()

            inspection = inspect_json_storage(settings.users_path, settings.integrity_key_path)
            report.check(
                f"{label}: offline check detects the change",
                not inspection.ok,
                inspection.describe(),
            )

            refused = False
            try:
                JsonStorage(
                    settings.users_path,
                    settings.integrity_key_path,
                    audit=audit,
                    clock=clock,
                )
            except IntegrityError:
                refused = True
            report.check(f"{label}: load refused (data not trusted)", refused)

            events = audit.events_for(AuditEvent.INTEGRITY_FAILURE)
            report.check(
                f"{label}: integrity failure audited",
                len(events) == 1,
                f"{len(events)} event(s)",
            )
            report.check(
                f"{label}: file not rewritten by failed load",
                settings.users_path.read_bytes() == before_load,
            )

            rows.append(
                (
                    label,
                    "detected" if not inspection.ok else "MISSED",
                    "refused" if refused else "LOADED",
                    str(len(events)),
                )
            )

        # --- wrong key ---------------------------------------------------
        directory = Path(tmp) / "wrong_key"
        audit = InMemoryAuditLog(clock=clock)
        settings = _baseline(directory, audit, clock)
        other_key = directory / "attacker.key"
        IntegritySigner.load_or_create(other_key)
        wrong_key = inspect_json_storage(settings.users_path, other_key)
        report.check(
            "wrong HMAC key is rejected",
            not wrong_key.ok,
            wrong_key.describe(),
        )
        rows.append(("wrong HMAC key", "detected" if not wrong_key.ok else "MISSED", "-", "-"))

    print(
        text_table(
            ("Tampering scenario", "Offline check", "Load behaviour", "Audit events"),
            rows,
        )
    )
    print()
    report.note(
        "The HMAC covers the entire user payload, so deleting a record or editing "
        "a non-secret field is detected just like a changed hash."
    )
    report.note(
        "Prototype limitation: the key sits next to the data file. An attacker who "
        "can read the key can forge the digest; production needs KMS/OS-keyring storage."
    )
    report.note(
        "JSON storage caches records in memory; tampering is detected at load or when "
        "verify_integrity() is called. SQLite re-verifies every row on read (Experiment 10)."
    )
    return report.finish()


if __name__ == "__main__":
    raise SystemExit(main())
