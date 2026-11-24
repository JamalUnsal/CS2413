"""Create demo accounts for the CLI and manual testing.

Run: ``python tools/seed_demo_users.py``
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from auth_system.audit import AuditLog
from auth_system.config import Settings
from auth_system.errors import AuthSystemError, IntegrityError
from auth_system.passwords import hash_password
from auth_system.policy import PasswordPolicy
from auth_system.registration import RegistrationService
from auth_system.storage import create_storage

DEMO_USERS = (
    ("alice", "jennifer"),
    ("bob", "Another-Str0ng-Pass!"),
    ("carol", "Third-Demo-Password-7!"),
)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Seed demo accounts (prototype only).")
    parser.add_argument("--data-dir", default=None, help="default: data")
    parser.add_argument("--backend", choices=("json", "sqlite"), default="json")
    parser.add_argument("--force", action="store_true", help="replace existing demo accounts")
    parser.add_argument(
        "--rounds",
        type=int,
        default=None,
        help="bcrypt work factor (default: Settings.bcrypt_rounds)",
    )
    args = parser.parse_args(argv)

    settings = Settings()
    if args.data_dir:
        settings = settings.with_data_dir(Path(args.data_dir))
    settings.data_dir.mkdir(parents=True, exist_ok=True)
    rounds = args.rounds or settings.bcrypt_rounds

    try:
        storage = create_storage(args.backend, settings)
    except IntegrityError as exc:
        print(f"Refusing to seed: credential data failed its integrity check.\n{exc}")
        return 1
    except (AuthSystemError, OSError, ValueError) as exc:
        print(f"Could not open storage: {exc}")
        return 1

    try:
        registrar = RegistrationService(
            storage=storage,
            policy=PasswordPolicy(settings),
            audit=AuditLog(settings.audit_log_path),
            settings=settings,
            hasher=lambda pw: hash_password(pw, rounds=rounds),
            clock=lambda: 1_700_000_000.0,
        )
        for username, password in DEMO_USERS:
            if storage.user_exists(username):
                if not args.force:
                    print(f"skip   {username} (already exists; use --force to replace)")
                    continue
                storage.delete_user(username)
            res = registrar.register(username, password)
            print(f"{'create' if res.success else 'fail  '} {username}")
        print()
        print(storage.verify_integrity().describe())
        print()
        print("Demo credentials (development only - never use in production):")
        for username, password in DEMO_USERS:
            print(f"  {username:6s} {password}")
        return 0
    finally:
        storage.close()


if __name__ == "__main__":
    sys.exit(main())
