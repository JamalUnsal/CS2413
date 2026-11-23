from __future__ import annotations

import argparse
import getpass
import sys
from datetime import datetime

from auth_system.auth import LoginResult
from auth_system.config import Settings
from auth_system.errors import AuthSystemError, IntegrityError
from auth_system.runtime import Runtime, build_runtime

RULE = "=" * 64
THIN_RULE = "-" * 64


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m auth_system",
        description="Team 9 password authentication prototype (CLI).",
    )
    parser.add_argument(
        "--backend",
        choices=("json", "sqlite"),
        default="json",
        help="storage backend to use (default: json)",
    )
    parser.add_argument(
        "--data-dir",
        default=None,
        help="directory for users, integrity key and audit files (default: data)",
    )
    parser.add_argument(
        "--gui",
        action="store_true",
        help="open the optional Tkinter desktop interface instead of the terminal menu",
    )
    args = parser.parse_args(argv)

    settings = Settings()
    if args.data_dir:
        settings = settings.with_data_dir(args.data_dir)

    if args.gui:
        try:
            from auth_system.gui import run as run_gui
        except ImportError as exc:
            print(f"FATAL: the desktop interface is unavailable: {exc}")
            print("Use the command-line interface instead: python -m auth_system")
            return 1
        return run_gui(settings, args.backend)

    try:
        runtime = build_runtime(settings, backend=args.backend)
    except IntegrityError as exc:
        print("FATAL: stored credential data failed its integrity check.")
        print(f"       {exc}")
        print("       Refusing to start. Investigate the data file before continuing.")
        return 1
    except (AuthSystemError, OSError, ValueError) as exc:
        print(f"FATAL: could not start the prototype: {exc}")
        return 1

    try:
        _main_menu(runtime)
    except (KeyboardInterrupt, EOFError):
        print("\nGoodbye.")
    finally:
        runtime.close()
    return 0


# ----------------------------------------------------------------------
# Menus
# ----------------------------------------------------------------------
def _main_menu(runtime: Runtime) -> None:
    while True:
        _print_header(runtime)
        print(" 1) Log in")
        print(" 2) Register new user                [not implemented]")
        print(" 3) Forgot password / reset")
        print(" 4) Check storage integrity")
        print(" 5) Quit")
        choice = _ask("Choose an option: ")

        if choice == "1":
            result = _login_flow(runtime)
            if result is not None and result.success:
                assert result.session_token is not None
                _authenticated_menu(runtime, result.session_token)
        elif choice == "2":
            print(
                "\nRegistration, password policy and strength scoring are not\n"
                "implemented yet. Use tools/seed_demo_users.py to create demo\n"
                "accounts until then.\n"
            )
        elif choice == "3":
            _reset_flow(runtime)
        elif choice == "4":
            report = runtime.storage.verify_integrity()
            print(f"\n{report.describe()}\n")
        elif choice == "5":
            print("Goodbye.")
            return
        else:
            print("Unknown option.")


def _authenticated_menu(runtime: Runtime, token: str) -> None:
    while True:
        session = runtime.auth.current_session(token)
        if session is None:
            print("\nYour session has expired. Please log in again.\n")
            return

        print(f"\n{THIN_RULE}")
        print(f" Signed in as {session.username}")
        print(f" Session expires {_format_time(session.expires_at)}")
        print(THIN_RULE)
        print(" 1) Change password")
        print(" 2) Enable MFA (TOTP)")
        print(" 3) Session details")
        print(" 4) Log out")
        choice = _ask("Choose an option: ")

        if choice == "1":
            _change_password_flow(runtime, token)
        elif choice == "2":
            _mfa_enrollment_flow(runtime, token)
        elif choice == "3":
            _session_details(runtime, token)
        elif choice == "4":
            runtime.auth.logout(token)
            print("\nLogged out.\n")
            return
        else:
            print("Unknown option.")


# ----------------------------------------------------------------------
# Flows
# ----------------------------------------------------------------------
def _login_flow(runtime: Runtime) -> LoginResult | None:
    username = _ask("Username: ")
    password = getpass.getpass("Password: ")
    result = runtime.auth.login(username, password)

    if not result.success and result.reason == "mfa_required":
        code = _ask("One-time code: ")
        result = runtime.auth.login(username, password, code)

    print(f"\n{result.message}")
    if not result.success and result.reason == "locked_out" and result.retry_after:
        print(f"Try again in about {int(result.retry_after)} second(s).")
    if result.success:
        print(f"Session expires {_format_time(result.session_expires_at)}.")
        print(
            "Session token (prototype only, keep it secret): "
            f"{result.session_token}\n"
        )
    return result


def _change_password_flow(runtime: Runtime, token: str) -> None:
    session = runtime.auth.current_session(token)
    if session is None:
        print("\nSession expired.\n")
        return

    old_password = getpass.getpass("Current password: ")
    new_password = getpass.getpass("New password: ")
    confirm = getpass.getpass("Confirm new password: ")
    if new_password != confirm:
        print("\nThe new passwords do not match.\n")
        return

    try:
        result = runtime.credentials.change_password(
            session.username,
            old_password,
            new_password,
            session_token=token,
        )
    except NotImplementedError as exc:
        print(f"\n[not implemented] {exc}\n")
        return
    except AuthSystemError as exc:
        print(f"\nPassword change failed: {exc}\n")
        return

    print(f"\n{result.message}\n")


def _reset_flow(runtime: Runtime) -> None:
    username = _ask("Username: ")
    request = runtime.credentials.request_password_reset(username)
    print(f"\n{request.message}")

    if request.token is None:
        print("(No token issued. In a real deployment the message would be identical.)\n")
        return

    print(f"Prototype reset token: {request.token}")
    new_password = getpass.getpass("New password: ")
    confirm = getpass.getpass("Confirm new password: ")
    if new_password != confirm:
        print("\nThe new passwords do not match (reset cancelled).\n")
        return

    try:
        result = runtime.credentials.reset_password(username, request.token, new_password)
    except NotImplementedError as exc:
        print(f"\n[not implemented] {exc}\n")
        return
    except AuthSystemError as exc:
        print(f"\nPassword reset failed: {exc}\n")
        return

    print(f"\n{result.message}\n")


def _mfa_enrollment_flow(runtime: Runtime, token: str) -> None:
    result = runtime.auth.begin_mfa_enrollment(token)
    print(f"\n{result.message}")
    if not result.success or result.enrollment is None:
        print()
        return

    print(f"Secret (manual entry): {result.enrollment.secret}")
    print(f"Provisioning URI (QR-compatible): {result.enrollment.provisioning_uri}")
    code = _ask("\nEnter the current 6-digit code to confirm: ")
    confirmation = runtime.auth.confirm_mfa_enrollment(token, code)
    print(f"\n{confirmation.message}\n")


def _session_details(runtime: Runtime, token: str) -> None:
    session = runtime.auth.current_session(token)
    if session is None:
        print("\nSession expired.\n")
        return
    remaining = runtime.sessions.remaining_seconds(session)
    print(f"\n{THIN_RULE}")
    print(f" Account:      {session.username}")
    print(f" Created:      {_format_time(session.created_at)}")
    print(f" Expires:      {_format_time(session.expires_at)}")
    print(f" Remaining:    {int(remaining)} second(s)")
    print(f" Fingerprint:  {session.fingerprint[:16]}... (token itself is not stored)")
    print(f"{THIN_RULE}\n")


# ----------------------------------------------------------------------
# Helpers
# ----------------------------------------------------------------------
def _print_header(runtime: Runtime) -> None:
    print(f"\n{RULE}")
    print(" Team 9 - Password Authentication Prototype")
    print(f" Backend: {runtime.storage.backend_name}    Data: {runtime.settings.data_dir}")
    print(RULE)


def _ask(prompt: str) -> str:
    return input(prompt).strip()


def _format_time(timestamp: float | None) -> str:
    if timestamp is None:
        return "unknown"
    return datetime.fromtimestamp(timestamp).strftime("%Y-%m-%d %H:%M:%S")


if __name__ == "__main__":
    sys.exit(main())
