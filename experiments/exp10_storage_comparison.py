"""Experiment 10 - Storage backend comparison (JSON vs SQLite).

OWNER: Shalom Olorunfemi.

Procedure
---------
For 1,000 synthetic accounts (fixed test hash; hashing is Experiment 2's cost,
not this experiment's variable):
  * measure bulk insert, single-record read and full-list read time;
  * run the same login through the authentication service (proves the
    authentication logic is unchanged by the backend);
  * hammer the backend from 8 threads, 20 updates each, and count errors;
  * directly tamper with one stored record and confirm detection;
  * report re-open behaviour and on-disk size.

Run: ``python -m experiments.exp10_storage_comparison [--users N]``
"""

from __future__ import annotations

import argparse
import json
import sqlite3
import tempfile
import threading
import time
from pathlib import Path

from auth_system import devtools
from auth_system.audit import NullAuditLog
from auth_system.errors import IntegrityError
from auth_system.models import UserRecord
from auth_system.runtime import build_runtime
from auth_system.storage import JsonStorage, create_storage
from experiments._common import Report, make_settings, text_table

PASSWORD = "SamePasswordForAll-9!"
EPOCH = 1_700_000_000.0
THREADS = 8
UPDATES_PER_THREAD = 20


def _build_records(count: int, password_hash: str) -> list[UserRecord]:
    return [
        UserRecord(
            username=f"user{index:04d}",
            password_hash=password_hash,
            created_at=EPOCH,
            updated_at=EPOCH,
            password_changed_at=EPOCH,
        )
        for index in range(count)
    ]


def _run_concurrent_updates(storage, count: int) -> tuple[float, int, int]:
    errors: list[int] = []

    def worker(worker_index: int) -> None:
        local_errors = 0
        username = f"user{worker_index * UPDATES_PER_THREAD:04d}"
        for _ in range(UPDATES_PER_THREAD):
            try:
                user = storage.get_user(username)
                if user is None:
                    local_errors += 1
                    continue
                user.failed_attempts += 1
                storage.save_user(user)
            except Exception:  # noqa: BLE001 - counting backend failures is the point
                local_errors += 1
        errors.append(local_errors)

    threads = [threading.Thread(target=worker, args=(index,)) for index in range(THREADS)]
    started = time.perf_counter()
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    elapsed = time.perf_counter() - started

    final = storage.get_user("user0000")
    final_counter = final.failed_attempts if final is not None else -1
    return elapsed, sum(errors), final_counter


def _tamper(directory: Path, backend: str, settings, password_hash: str) -> None:
    if backend == "json":
        document = json.loads(settings.users_path.read_text(encoding="utf-8"))
        document["users"]["user0000"]["password_hash"] = "tampered-by-attacker"
        settings.users_path.write_text(
            json.dumps(document, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        return

    connection = sqlite3.connect(str(settings.sqlite_path))
    try:
        connection.execute(
            "UPDATE users SET record = replace(record, ?, ?) WHERE username = ?",
            (password_hash, "tampered-by-attacker", "user0000"),
        )
        connection.commit()
    finally:
        connection.close()


def _reopen_detects(backend: str, storage, settings) -> tuple[bool, str]:
    if backend == "json":
        try:
            reopened = JsonStorage(
                settings.users_path,
                settings.integrity_key_path,
                audit=NullAuditLog(),
            )
        except IntegrityError:
            return True, "refused to load on re-open"
        reopened.close()
        return False, "loaded tampered data"

    try:
        storage.get_user("user0000")
    except IntegrityError:
        return True, "row signature verified on read"
    return False, "returned tampered data"


def _size_kb(backend: str, settings) -> float:
    paths = [settings.users_path] if backend == "json" else [
        settings.sqlite_path,
        settings.sqlite_path.with_name(settings.sqlite_path.name + "-wal"),
        settings.sqlite_path.with_name(settings.sqlite_path.name + "-shm"),
    ]
    return sum(path.stat().st_size for path in paths if path.exists()) / 1024.0


def _run_backend(backend: str, directory: Path, count: int, report: Report) -> dict[str, object]:
    settings = make_settings(directory)
    audit = NullAuditLog()
    password_hash = devtools.dev_hash_password(PASSWORD, rounds=settings.bcrypt_rounds)
    records = _build_records(count, password_hash)

    storage = create_storage(backend, settings, audit=audit)
    try:
        started = time.perf_counter()
        for record in records:
            storage.save_user(record)
        insert_seconds = time.perf_counter() - started

        sample_names = [f"user{index:04d}" for index in range(0, count, max(1, count // 100))]
        started = time.perf_counter()
        for username in sample_names:
            storage.get_user(username)
        read_ms = (time.perf_counter() - started) / len(sample_names) * 1000.0

        started = time.perf_counter()
        listed = storage.list_users()
        list_seconds = time.perf_counter() - started
        report.check(f"{backend}: all records readable", len(listed) == count, f"{len(listed)}/{count}")

        # Same authentication code path on both backends.
        runtime = build_runtime(settings, backend=backend, audit=audit)
        try:
            login = runtime.auth.login(f"user{count // 2:04d}", PASSWORD)
        finally:
            runtime.close()
        report.check(f"{backend}: login uses the same auth logic", login.success)

        concurrent_seconds, concurrent_errors, final_counter = _run_concurrent_updates(
            storage, count
        )
        report.check(f"{backend}: no concurrency errors", concurrent_errors == 0, str(concurrent_errors))
        report.check(
            f"{backend}: concurrent updates all applied",
            final_counter == UPDATES_PER_THREAD,
            f"counter={final_counter}/{UPDATES_PER_THREAD}",
        )
        integrity_after = storage.verify_integrity()
        report.check(f"{backend}: integrity valid after concurrency", integrity_after.ok)

        _tamper(directory, backend, settings, password_hash)
        tamper_report = storage.verify_integrity()
        report.check(
            f"{backend}: tampering detected by verify_integrity",
            not tamper_report.ok,
            tamper_report.describe(),
        )
        reopened, detail = _reopen_detects(backend, storage, settings)
        report.check(f"{backend}: tampered data not trusted on access", reopened, detail)

        return {
            "backend": backend,
            "insert_seconds": insert_seconds,
            "read_ms": read_ms,
            "list_seconds": list_seconds,
            "concurrent_seconds": concurrent_seconds,
            "concurrent_errors": concurrent_errors,
            "counter": final_counter,
            "reopen": reopened,
        }
    finally:
        storage.close()


def run_backend(backend: str, directory: Path, count: int, report: Report) -> dict[str, object]:
    result = _run_backend(backend, directory, count, report)
    # Measure on-disk size after close so SQLite has checkpointed its WAL.
    result["size_kb"] = _size_kb(backend, make_settings(directory))
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--users", type=int, default=1000, help="number of synthetic accounts")
    args = parser.parse_args(argv)

    report = Report(
        "Experiment 10 - Storage backend comparison (JSON vs SQLite)",
        f"Protocol: {args.users} synthetic accounts per backend, including concurrency and tampering.",
    )
    results = []
    with tempfile.TemporaryDirectory() as tmp:
        for backend in ("json", "sqlite"):
            backend_dir = Path(tmp) / backend
            results.append(run_backend(backend, backend_dir, args.users, report))

    print(
        text_table(
            (
                "Backend",
                f"Insert {args.users} (s)",
                "Read 1 (ms)",
                "List all (s)",
                "Threaded (s)",
                "Errors",
                "Size (KB)",
            ),
            [
                (
                    item["backend"],
                    f"{item['insert_seconds']:.2f}",
                    f"{item['read_ms']:.3f}",
                    f"{item['list_seconds']:.4f}",
                    f"{item['concurrent_seconds']:.2f}",
                    str(item["concurrent_errors"]),
                    f"{item['size_kb']:.1f}",
                )
                for item in results
            ],
        )
    )
    print()
    report.note(
        "JSON rewrites the whole file on every save (O(n) per write), while SQLite "
        "updates one row in a transaction - the insert/update gap grows with account count."
    )
    report.note(
        "JSON detects tampering when the file is loaded or verify_integrity() is called; "
        "SQLite verifies each row signature on every read."
    )
    report.note(
        "In-process threading is safe for both backends. JSON is NOT safe across processes "
        "without an external file lock; SQLite provides cross-process locking and WAL."
    )
    report.note(
        "The same authentication service was used unchanged against both backends, "
        "demonstrating the storage interface works as intended."
    )
    return report.finish()


if __name__ == "__main__":
    raise SystemExit(main())
