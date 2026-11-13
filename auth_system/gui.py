"""Optional Tkinter desktop front end for the authentication prototype.

OWNER: Sandeep Singh ("primary login menu interface").

This window is a thin view over exactly the same services as the CLI
(``auth_system.cli``): it calls ``AuthService`` and ``CredentialManager`` and
contains **no authentication logic of its own**.  The CLI remains the reference
interface used by the tests and experiments; this module only adds a mouse-
driven presentation for demos.

Features
--------
* Dark theme by default (palette below) with a light/dark toggle in the header.
* "Welcome, <username>" on the screen shown after a successful login.
* Optional QR code for TOTP enrollment: if the third-party ``qrcode`` and
  ``Pillow`` packages are installed the provisioning URI is rendered as a
  scannable image; otherwise the secret and URI are still shown as text, so the
  core project keeps working with no extra dependencies.

Launch::

    python -m auth_system --gui
    python -m auth_system.gui --backend sqlite

Tkinter ships with the standard Python distribution.  If no display is
available the CLI still works.
"""

from __future__ import annotations

import argparse
import sys
import tkinter as tk
from datetime import datetime
from tkinter import messagebox, ttk

from auth_system.auth import LoginResult
from auth_system.config import Settings
from auth_system.errors import AuthSystemError, IntegrityError
from auth_system.runtime import Runtime, build_runtime

TITLE = "Team 9 - Password Authentication Prototype"
PROTOTYPE_NOTE = "Prototype only: never use these accounts or tokens outside the lab."

# Dark palette (default) and the light counterpart used by the toggle.
DARK_PALETTE = {
    "main_bg": "#212121",
    "sidebar_bg": "#171717",
    "surface": "#2F2F2F",
    "hover": "#383838",
    "text": "#F4F4F4",
    "text_muted": "#B4B4B4",
    "border": "#424242",
    "accent": "#10A37F",
    "accent_hover": "#0E8C6D",
    "danger": "#FF6B6B",
}

LIGHT_PALETTE = {
    "main_bg": "#F5F5F5",
    "sidebar_bg": "#FFFFFF",
    "surface": "#FFFFFF",
    "hover": "#E6E6E6",
    "text": "#212121",
    "text_muted": "#5A5A5A",
    "border": "#C9C9C9",
    "accent": "#0E8C6D",
    "accent_hover": "#0B6E55",
    "danger": "#B00020",
}


class AuthApp(tk.Tk):
    """Main window with an unauthenticated and an authenticated screen."""

    def __init__(self, runtime: Runtime) -> None:
        super().__init__()
        self.runtime = runtime
        self.session_token: str | None = None
        self.username: str | None = None
        self.dark_mode = True
        self.dark_var = tk.BooleanVar(value=True)

        self.title(TITLE)
        self.geometry("620x560")
        self.minsize(560, 520)
        self.protocol("WM_DELETE_WINDOW", self.destroy)
        self._apply_theme()

        self.container = ttk.Frame(self, style="App.TFrame")
        self.container.pack(fill="both", expand=True)
        self._build_header()

        ttk.Separator(self.container, orient="horizontal").pack(fill="x")

        self.body = ttk.Frame(self.container, style="App.TFrame", padding=20)
        self.body.pack(fill="both", expand=True)

        self.status_label: ttk.Label | None = None
        self.show_login()

    # ------------------------------------------------------------------
    # Theming
    # ------------------------------------------------------------------
    def _palette(self) -> dict[str, str]:
        return DARK_PALETTE if self.dark_mode else LIGHT_PALETTE

    def _build_header(self) -> None:
        header = ttk.Frame(self.container, style="Sidebar.TFrame", padding=(20, 14))
        header.pack(fill="x")

        titles = ttk.Frame(header, style="Sidebar.TFrame")
        titles.pack(side="left")
        ttk.Label(
            titles, text=TITLE, style="Header.TLabel"
        ).pack(anchor="w")
        ttk.Label(
            titles,
            text="Design, implementation and security evaluation",
            style="HeaderMuted.TLabel",
        ).pack(anchor="w")

        ttk.Checkbutton(
            header,
            text="Dark mode",
            variable=self.dark_var,
            command=self._toggle_theme,
            style="Header.TCheckbutton",
        ).pack(side="right")

    def _toggle_theme(self) -> None:
        self.dark_mode = bool(self.dark_var.get())
        self._apply_theme()

    def _apply_theme(self) -> None:
        colors = self._palette()
        style = ttk.Style(self)
        style.theme_use("clam")  # clam honours custom background colours
        self.configure(bg=colors["main_bg"])

        style.configure(
            ".",
            background=colors["main_bg"],
            foreground=colors["text"],
            fieldbackground=colors["surface"],
            bordercolor=colors["border"],
            lightcolor=colors["surface"],
            darkcolor=colors["surface"],
            focuscolor=colors["accent"],
        )
        style.configure("App.TFrame", background=colors["main_bg"])
        style.configure("Sidebar.TFrame", background=colors["sidebar_bg"])
        style.configure("Surface.TFrame", background=colors["surface"])

        style.configure(
            "Title.TLabel",
            background=colors["main_bg"],
            foreground=colors["text"],
            font=("Segoe UI", 15, "bold"),
        )
        style.configure(
            "Welcome.TLabel",
            background=colors["main_bg"],
            foreground=colors["accent"],
            font=("Segoe UI", 20, "bold"),
        )
        style.configure(
            "Header.TLabel",
            background=colors["sidebar_bg"],
            foreground=colors["text"],
            font=("Segoe UI", 14, "bold"),
        )
        style.configure(
            "HeaderMuted.TLabel",
            background=colors["sidebar_bg"],
            foreground=colors["text_muted"],
            font=("Segoe UI", 9),
        )
        style.configure(
            "Subtitle.TLabel",
            background=colors["main_bg"],
            foreground=colors["text_muted"],
            font=("Segoe UI", 10),
        )
        style.configure(
            "Body.TLabel", background=colors["main_bg"], foreground=colors["text"]
        )
        style.configure(
            "Muted.TLabel",
            background=colors["main_bg"],
            foreground=colors["text_muted"],
        )
        style.configure(
            "Danger.TLabel",
            background=colors["main_bg"],
            foreground=colors["danger"],
        )

        style.configure("TSeparator", background=colors["border"])

        style.configure(
            "TButton",
            background=colors["surface"],
            foreground=colors["text"],
            bordercolor=colors["border"],
            focusthickness=0,
            padding=(12, 6),
        )
        style.map(
            "TButton",
            background=[
                ("active", colors["hover"]),
                ("pressed", colors["hover"]),
                ("disabled", colors["main_bg"]),
            ],
            foreground=[("disabled", colors["text_muted"])],
        )
        style.configure(
            "Accent.TButton",
            background=colors["accent"],
            foreground="#0B0B0B",
            bordercolor=colors["accent"],
            focusthickness=0,
            padding=(12, 6),
            font=("Segoe UI", 10, "bold"),
        )
        style.map(
            "Accent.TButton",
            background=[
                ("active", colors["accent_hover"]),
                ("pressed", colors["accent_hover"]),
                ("disabled", colors["surface"]),
            ],
            foreground=[("disabled", colors["text_muted"])],
        )

        style.configure(
            "TCheckbutton", background=colors["main_bg"], foreground=colors["text"]
        )
        style.map(
            "TCheckbutton",
            background=[("active", colors["main_bg"])],
            foreground=[("disabled", colors["text_muted"])],
        )
        style.configure(
            "Header.TCheckbutton",
            background=colors["sidebar_bg"],
            foreground=colors["text_muted"],
        )
        style.map(
            "Header.TCheckbutton",
            background=[("active", colors["sidebar_bg"])],
        )

        style.configure(
            "TEntry",
            fieldbackground=colors["surface"],
            foreground=colors["text"],
            bordercolor=colors["border"],
            insertcolor=colors["text"],
            padding=5,
        )
        style.map(
            "TEntry",
            fieldbackground=[
                ("readonly", colors["surface"]),
                ("disabled", colors["main_bg"]),
            ],
            foreground=[("disabled", colors["text_muted"])],
        )

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------
    def _clear(self) -> None:
        for child in self.body.winfo_children():
            child.destroy()
        self.status_label = None

    def _status(self, text: str, *, error: bool = False) -> None:
        if self.status_label is None:
            return
        try:
            if not self.status_label.winfo_exists():
                return
            self.status_label.configure(
                text=text, style="Danger.TLabel" if error else "Muted.TLabel"
            )
        except tk.TclError:
            return

    def _new_status(self, parent: tk.Widget) -> None:
        self.status_label = ttk.Label(
            parent, text="", style="Muted.TLabel", wraplength=560
        )
        self.status_label.pack(anchor="w", pady=(12, 0))

    def _set_cursor(self, cursor: str) -> None:
        try:
            self.configure(cursor=cursor)
            self.update_idletasks()
        except tk.TclError:
            pass

    def _labeled_entry(
        self,
        parent: tk.Widget,
        row: int,
        label: str,
        *,
        show: str | None = None,
        width: int = 34,
    ) -> ttk.Entry:
        ttk.Label(parent, text=label, style="Body.TLabel").grid(
            row=row, column=0, sticky="w", pady=4, padx=(0, 12)
        )
        entry = ttk.Entry(parent, width=width, show=show or "")
        entry.grid(row=row, column=1, sticky="we", pady=4)
        parent.columnconfigure(1, weight=1)
        return entry

    def _require_session(self) -> bool:
        if (
            self.session_token
            and self.runtime.auth.current_session(self.session_token) is not None
        ):
            return True
        self.show_login("Your session has expired. Please log in again.", error=True)
        return False

    # ------------------------------------------------------------------
    # Unauthenticated screen
    # ------------------------------------------------------------------
    def show_login(self, message: str | None = None, *, error: bool = False) -> None:
        self.session_token = None
        self.username = None
        self._clear()

        frame = ttk.Frame(self.body, style="App.TFrame")
        frame.pack(fill="both", expand=True)

        ttk.Label(frame, text="Sign in", style="Title.TLabel").pack(anchor="w")
        ttk.Label(
            frame, text="Enter your credentials to continue.", style="Subtitle.TLabel"
        ).pack(anchor="w", pady=(2, 14))

        form = ttk.Frame(frame, style="App.TFrame")
        form.pack(fill="x")
        self.login_username = self._labeled_entry(form, 0, "Username")
        self.login_password = self._labeled_entry(form, 1, "Password", show="*")
        self.login_code = self._labeled_entry(
            form, 2, "One-time code (only if MFA is enabled)"
        )

        show_password = tk.BooleanVar(value=False)

        def toggle_password() -> None:
            self.login_password.configure(show="" if show_password.get() else "*")

        ttk.Checkbutton(
            form,
            text="Show password",
            variable=show_password,
            command=toggle_password,
        ).grid(row=3, column=1, sticky="w", pady=(0, 8))

        primary = ttk.Frame(frame, style="App.TFrame")
        primary.pack(fill="x", pady=(8, 6))
        ttk.Button(
            primary, text="Log in", style="Accent.TButton", command=self._do_login
        ).pack(side="left")

        secondary = ttk.Frame(frame, style="App.TFrame")
        secondary.pack(fill="x", pady=(2, 6))
        ttk.Button(
            secondary, text="Forgot password", command=self._forgot_password_dialog
        ).pack(side="left")
        ttk.Button(
            secondary, text="Check storage integrity", command=self._integrity_check
        ).pack(side="left", padx=(8, 0))
        ttk.Button(
            secondary, text="Register (not implemented)", command=self._registration_notice
        ).pack(side="left", padx=(8, 0))

        ttk.Button(frame, text="Quit", command=self.destroy).pack(anchor="e", pady=(4, 0))
        self._new_status(frame)
        if message:
            self._status(message, error=error)

        self.login_username.focus_set()
        for widget in (self.login_username, self.login_password, self.login_code):
            widget.bind("<Return>", lambda _event: self._do_login())

    def _do_login(self) -> None:
        username = self.login_username.get().strip()
        password = self.login_password.get()
        code = self.login_code.get().strip() or None

        self._set_cursor("watch")
        try:
            result: LoginResult = self.runtime.auth.login(username, password, code)
        except AuthSystemError as exc:
            self._status(f"Login failed: {exc}", error=True)
            return
        finally:
            self._set_cursor("")

        if result.success:
            session = self.runtime.auth.current_session(result.session_token)
            self.session_token = result.session_token
            self.username = session.username if session else username
            if session is None:
                self.show_login(
                    "The session could not be validated. Please log in again.",
                    error=True,
                )
                return
            self.show_session()
            return

        if result.reason == "mfa_required":
            self._status(
                "Enter the 6-digit code from your authenticator app and log in again.",
                error=True,
            )
            self.login_code.focus_set()
            return

        if result.reason == "locked_out" and result.retry_after:
            self._status(
                f"{result.message} Try again in about {int(result.retry_after)} "
                "second(s).",
                error=True,
            )
            return

        self._status(result.message, error=True)

    # ------------------------------------------------------------------
    # Authenticated screen
    # ------------------------------------------------------------------
    def show_session(self) -> None:
        session = self.runtime.auth.current_session(self.session_token)
        if session is None:
            self.show_login("Your session has expired. Please log in again.", error=True)
            return

        user = self.runtime.storage.get_user(session.username)
        self._clear()
        frame = ttk.Frame(self.body, style="App.TFrame")
        frame.pack(fill="both", expand=True)

        ttk.Label(
            frame, text=f"Welcome, {session.username}", style="Welcome.TLabel"
        ).pack(anchor="w")
        ttk.Label(
            frame, text="You are signed in.", style="Subtitle.TLabel"
        ).pack(anchor="w", pady=(2, 16))

        info = ttk.Frame(frame, style="App.TFrame")
        info.pack(fill="x", pady=(0, 16))
        rows = [
            ("Account", session.username),
            ("MFA", "enabled" if (user and user.mfa_enabled) else "not enabled"),
            ("Session expires", _format_time(session.expires_at)),
            (
                "Time remaining",
                f"{int(self.runtime.sessions.remaining_seconds(session))} second(s)",
            ),
        ]
        for index, (label, value) in enumerate(rows):
            ttk.Label(info, text=label, style="Muted.TLabel").grid(
                row=index, column=0, sticky="w", padx=(0, 12), pady=2
            )
            ttk.Label(info, text=value, style="Body.TLabel").grid(
                row=index, column=1, sticky="w", pady=2
            )

        actions = ttk.Frame(frame, style="App.TFrame")
        actions.pack(fill="x", pady=(0, 8))
        ttk.Button(
            actions, text="Change password", command=self._change_password_dialog
        ).pack(side="left")
        ttk.Button(
            actions, text="Enable MFA (TOTP)", command=self._mfa_dialog
        ).pack(side="left", padx=(8, 0))
        ttk.Button(
            actions, text="Session details", command=self._session_details
        ).pack(side="left", padx=(8, 0))
        ttk.Button(actions, text="Log out", command=self._logout).pack(
            side="left", padx=(8, 0)
        )

        tools = ttk.Frame(frame, style="App.TFrame")
        tools.pack(fill="x", pady=(0, 4))
        ttk.Button(
            tools, text="Check storage integrity", command=self._integrity_check
        ).pack(side="left")

        ttk.Label(
            frame, text=PROTOTYPE_NOTE, style="Muted.TLabel", wraplength=560
        ).pack(anchor="w", pady=(16, 0))
        self._new_status(frame)

    def _logout(self) -> None:
        if self.session_token:
            self.runtime.auth.logout(self.session_token)
        self.show_login("Logged out.")

    # ------------------------------------------------------------------
    # Change password
    # ------------------------------------------------------------------
    def _change_password_dialog(self) -> None:
        if not self._require_session():
            return

        dialog = self._dialog("Change password")
        body = ttk.Frame(dialog, padding=16)
        body.pack(fill="both", expand=True)

        old = self._labeled_entry(body, 0, "Current password", show="*", width=28)
        new = self._labeled_entry(body, 1, "New password", show="*", width=28)
        confirm = self._labeled_entry(body, 2, "Confirm new password", show="*", width=28)
        status = ttk.Label(body, text="", style="Danger.TLabel", wraplength=360)
        status.grid(row=3, column=0, columnspan=2, sticky="w", pady=(8, 0))

        buttons = ttk.Frame(body)
        buttons.grid(row=4, column=0, columnspan=2, sticky="e", pady=(12, 0))

        def submit() -> None:
            if new.get() != confirm.get():
                status.configure(text="The new passwords do not match.")
                return
            self._set_cursor("watch")
            try:
                result = self.runtime.credentials.change_password(
                    self.username or "",
                    old.get(),
                    new.get(),
                    session_token=self.session_token,
                )
            except NotImplementedError as exc:
                self._close_dialog(dialog)
                messagebox.showinfo("Not implemented", str(exc), parent=self)
                return
            except AuthSystemError as exc:
                status.configure(text=f"Password change failed: {exc}")
                return
            finally:
                self._set_cursor("")

            self._close_dialog(dialog)
            if result.success:
                # Every session was invalidated, so return to the login screen.
                self.show_login(result.message)
            else:
                self._status(result.message, error=True)

        ttk.Button(buttons, text="Cancel", command=lambda: self._close_dialog(dialog)).pack(
            side="right"
        )
        ttk.Button(
            buttons, text="Change password", style="Accent.TButton", command=submit
        ).pack(side="right", padx=(0, 8))

        old.focus_set()
        for widget in (old, new, confirm):
            widget.bind("<Return>", lambda _event: submit())

    # ------------------------------------------------------------------
    # MFA enrollment
    # ------------------------------------------------------------------
    def _mfa_dialog(self) -> None:
        if not self._require_session():
            return

        result = self.runtime.auth.begin_mfa_enrollment(self.session_token)
        if not result.success or result.enrollment is None:
            messagebox.showinfo("Multi-factor authentication", result.message, parent=self)
            return

        enrollment = result.enrollment
        dialog = self._dialog("Enable multi-factor authentication")
        body = ttk.Frame(dialog, padding=16)
        body.pack(fill="both", expand=True)

        ttk.Label(
            body,
            text="1. Add this account to your authenticator app.",
            style="Subtitle.TLabel",
        ).pack(anchor="w")

        photo = _qr_photo(enrollment.provisioning_uri, dark=self.dark_mode)
        if photo is not None:
            qr_label = ttk.Label(body, image=photo)
            qr_label.image = photo  # keep a reference so Tk does not collect it
            qr_label.pack(anchor="center", pady=(8, 4))
        else:
            ttk.Label(
                body,
                text="Install the optional 'qrcode' and 'Pillow' packages to show a "
                "scannable QR code here, or enter the secret below manually.",
                style="Muted.TLabel",
                wraplength=420,
            ).pack(anchor="w", pady=(8, 4))

        secret_row = ttk.Frame(body)
        secret_row.pack(fill="x", pady=(4, 4))
        ttk.Label(secret_row, text="Secret:", style="Muted.TLabel").pack(side="left")
        secret_entry = ttk.Entry(secret_row, width=40)
        secret_entry.insert(0, enrollment.secret)
        secret_entry.configure(state="readonly")
        secret_entry.pack(side="left", padx=(8, 4), fill="x", expand=True)
        ttk.Button(
            secret_row, text="Copy", command=lambda: self._copy(enrollment.secret)
        ).pack(side="left")

        uri_row = ttk.Frame(body)
        uri_row.pack(fill="x", pady=(0, 8))
        ttk.Label(uri_row, text="URI:", style="Muted.TLabel").pack(side="left")
        uri_entry = ttk.Entry(uri_row, width=40)
        uri_entry.insert(0, enrollment.provisioning_uri)
        uri_entry.configure(state="readonly")
        uri_entry.pack(side="left", padx=(8, 4), fill="x", expand=True)
        ttk.Button(
            uri_row,
            text="Copy",
            command=lambda: self._copy(enrollment.provisioning_uri),
        ).pack(side="left")

        ttk.Label(
            body,
            text="2. Enter the current 6-digit code to confirm.",
            style="Subtitle.TLabel",
        ).pack(anchor="w", pady=(6, 4))
        code = ttk.Entry(body, width=12)
        code.pack(anchor="w")
        status = ttk.Label(body, text="", style="Danger.TLabel", wraplength=360)
        status.pack(anchor="w", pady=(8, 0))

        buttons = ttk.Frame(body)
        buttons.pack(fill="x", pady=(12, 0))
        ttk.Button(buttons, text="Cancel", command=lambda: self._close_dialog(dialog)).pack(
            side="right"
        )

        def confirm_code() -> None:
            confirmation = self.runtime.auth.confirm_mfa_enrollment(
                self.session_token, code.get()
            )
            if not confirmation.success:
                status.configure(text=confirmation.message)
                return
            self._close_dialog(dialog)
            messagebox.showinfo(
                "Multi-factor authentication", confirmation.message, parent=self
            )
            self.show_session()

        ttk.Button(
            buttons, text="Confirm", style="Accent.TButton", command=confirm_code
        ).pack(side="right", padx=(0, 8))
        code.bind("<Return>", lambda _event: confirm_code())
        code.focus_set()

    def _copy(self, value: str) -> None:
        self.clipboard_clear()
        self.clipboard_append(value)

    # ------------------------------------------------------------------
    # Reset flow
    # ------------------------------------------------------------------
    def _forgot_password_dialog(self) -> None:
        dialog = self._dialog("Reset password")
        body = ttk.Frame(dialog, padding=16)
        body.pack(fill="both", expand=True)

        ttk.Label(body, text="Reset your password", style="Title.TLabel").pack(anchor="w")
        ttk.Label(
            body,
            text="Enter your username to request a token. The response is the same "
            "whether or not the account exists.",
            style="Muted.TLabel",
            wraplength=420,
        ).pack(anchor="w", pady=(4, 12))

        form = ttk.Frame(body)
        form.pack(fill="x")
        username = self._labeled_entry(form, 0, "Username", width=28)
        token = self._labeled_entry(form, 1, "Reset token", width=28)
        token.configure(state="readonly")
        new = self._labeled_entry(form, 2, "New password", show="*", width=28)
        new.configure(state="disabled")
        confirm = self._labeled_entry(form, 3, "Confirm new password", show="*", width=28)
        confirm.configure(state="disabled")

        status = ttk.Label(body, text="", style="Muted.TLabel", wraplength=420)
        status.pack(anchor="w", pady=(8, 0))

        buttons = ttk.Frame(body)
        buttons.pack(fill="x", pady=(12, 0))
        ttk.Button(buttons, text="Cancel", command=lambda: self._close_dialog(dialog)).pack(
            side="right"
        )
        set_button = ttk.Button(buttons, text="Set new password", style="Accent.TButton")
        set_button.pack(side="right", padx=(0, 8))
        set_button.state(["disabled"])

        def request_token() -> None:
            request = self.runtime.credentials.request_password_reset(
                username.get().strip()
            )
            status.configure(text=request.message, style="Muted.TLabel")
            if request.token is None:
                return
            token.configure(state="normal")
            token.delete(0, "end")
            token.insert(0, request.token)
            token.configure(state="readonly")
            new.configure(state="normal")
            confirm.configure(state="normal")
            set_button.state(["!disabled"])
            status.configure(
                text=request.message
                + " Prototype only: the token is shown here because there is no "
                "email delivery.",
                style="Muted.TLabel",
            )
            new.focus_set()

        def set_password() -> None:
            if new.get() != confirm.get():
                status.configure(
                    text="The new passwords do not match.", style="Danger.TLabel"
                )
                return
            self._set_cursor("watch")
            try:
                result = self.runtime.credentials.reset_password(
                    username.get().strip(), token.get(), new.get()
                )
            except NotImplementedError as exc:
                self._close_dialog(dialog)
                messagebox.showinfo("Not implemented", str(exc), parent=self)
                return
            except AuthSystemError as exc:
                status.configure(
                    text=f"Password reset failed: {exc}", style="Danger.TLabel"
                )
                return
            finally:
                self._set_cursor("")

            self._close_dialog(dialog)
            self.show_login(result.message, error=not result.success)

        ttk.Button(buttons, text="Request token", command=request_token).pack(
            side="right", padx=(0, 8)
        )
        set_button.configure(command=set_password)

        username.focus_set()
        username.bind("<Return>", lambda _event: request_token())
        new.bind("<Return>", lambda _event: set_password())
        confirm.bind("<Return>", lambda _event: set_password())

    # ------------------------------------------------------------------
    # Session details / integrity / registration notice
    # ------------------------------------------------------------------
    def _session_details(self) -> None:
        session = self.runtime.auth.current_session(self.session_token)
        if session is None:
            self._require_session()
            return
        remaining = int(self.runtime.sessions.remaining_seconds(session))
        messagebox.showinfo(
            "Session details",
            f"Account: {session.username}\n"
            f"Created: {_format_time(session.created_at)}\n"
            f"Expires: {_format_time(session.expires_at)}\n"
            f"Remaining: {remaining} second(s)\n"
            f"Fingerprint: {session.fingerprint[:16]}...\n\n"
            "Only the SHA-256 fingerprint is stored; the raw token is never kept.",
            parent=self,
        )

    def _integrity_check(self) -> None:
        report = self.runtime.storage.verify_integrity()
        if report.ok:
            messagebox.showinfo("Storage integrity", report.describe(), parent=self)
        else:
            messagebox.showerror("Storage integrity", report.describe(), parent=self)

    def _registration_notice(self) -> None:
        messagebox.showinfo(
            "Registration",
            "Registration, password policy and strength scoring are not "
            "implemented yet.\n\nUse tools/seed_demo_users.py to create demo "
            "accounts until then.",
            parent=self,
        )

    # ------------------------------------------------------------------
    # Window plumbing
    # ------------------------------------------------------------------
    def _dialog(self, title: str) -> tk.Toplevel:
        dialog = tk.Toplevel(self)
        dialog.title(title)
        dialog.configure(bg=self._palette()["main_bg"])
        dialog.transient(self)
        dialog.resizable(False, False)
        dialog.grab_set()
        return dialog

    def _close_dialog(self, dialog: tk.Toplevel) -> None:
        try:
            dialog.grab_release()
            dialog.destroy()
        except tk.TclError:
            pass


def _qr_photo(uri: str, *, dark: bool = True):
    """Return a Tk image for ``uri``, or ``None`` when the optional deps are absent.

    ``qrcode`` and ``Pillow`` are deliberately optional: the MFA dialog falls
    back to showing the secret and provisioning URI as text when they are not
    installed, so the core project has no extra runtime dependency.
    """
    try:
        import qrcode
        from PIL import ImageTk
    except Exception:  # pragma: no cover - depends on optional packages
        return None

    try:
        foreground = "#F4F4F4" if dark else "#212121"
        background = "#2F2F2F" if dark else "#FFFFFF"
        code = qrcode.QRCode(
            border=2,
            box_size=6,
            error_correction=qrcode.constants.ERROR_CORRECT_M,
        )
        code.add_data(uri)
        code.make(fit=True)
        image = code.make_image(fill_color=foreground, back_color=background)
        return ImageTk.PhotoImage(image)
    except Exception:  # pragma: no cover - defensive: never break enrollment
        return None


def _format_time(timestamp: float | None) -> str:
    if timestamp is None:
        return "unknown"
    return datetime.fromtimestamp(timestamp).strftime("%Y-%m-%d %H:%M:%S")


def _fatal(message: str) -> None:
    try:
        root = tk.Tk()
        root.withdraw()
        messagebox.showerror(TITLE, message)
        root.destroy()
    except tk.TclError:
        print(f"FATAL: {message}", file=sys.stderr)


# ----------------------------------------------------------------------
# Entry points
# ----------------------------------------------------------------------
def run(settings: Settings, backend: str = "json") -> int:
    """Build the runtime and run the window.  Returns a process exit code."""
    try:
        runtime = build_runtime(settings, backend=backend)
    except IntegrityError as exc:
        _fatal(
            "Stored credential data failed its integrity check.\n\n"
            f"{exc}\n\nRefusing to start. Investigate the data file first."
        )
        return 1
    except (AuthSystemError, OSError, ValueError) as exc:
        _fatal(f"Could not start the prototype:\n\n{exc}")
        return 1

    try:
        app = AuthApp(runtime)
    except tk.TclError as exc:
        runtime.close()
        _fatal(
            "Could not open a window:\n\n"
            f"{exc}\n\nUse the command-line interface instead: python -m auth_system"
        )
        return 1

    try:
        app.mainloop()
    finally:
        runtime.close()
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m auth_system.gui",
        description="Team 9 password authentication prototype (desktop interface).",
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
    args = parser.parse_args(argv)

    settings = Settings()
    if args.data_dir:
        settings = settings.with_data_dir(args.data_dir)
    return run(settings, args.backend)


if __name__ == "__main__":
    sys.exit(main())
