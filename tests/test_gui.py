"""Smoke tests for the optional Tkinter interface (owner: Sandeep Singh).

The tests skip automatically when no display is available (e.g. a headless CI
runner), so the CLI suite stays portable.
"""

from __future__ import annotations

import pytest

import auth_system.gui as gui
from auth_system import cli
from tests.support import seed

PASSWORD = "Correct-Horse-Battery-9!"


def test_gui_module_exposes_entry_points():
    tkinter = pytest.importorskip("tkinter")

    assert callable(gui.run)
    assert callable(gui.main)
    assert issubclass(gui.AuthApp, tkinter.Tk)


def test_cli_gui_flag_delegates_to_the_window(tmp_path, monkeypatch):
    calls: list[tuple[object, str]] = []

    def fake_run(settings, backend):
        calls.append((settings, backend))
        return 0

    monkeypatch.setattr(gui, "run", fake_run)

    exit_code = cli.main(
        ["--data-dir", str(tmp_path), "--backend", "sqlite", "--gui"]
    )

    assert exit_code == 0
    assert len(calls) == 1
    settings, backend = calls[0]
    assert settings.data_dir == tmp_path
    assert backend == "sqlite"


def _make_app(runtime):
    tkinter = pytest.importorskip("tkinter")
    try:
        app = gui.AuthApp(runtime)
    except tkinter.TclError:
        pytest.skip("no display available")
    app.withdraw()
    return app


def test_window_constructs_without_errors(runtime):
    app = _make_app(runtime)
    try:
        app.update_idletasks()
    finally:
        app.destroy()


def test_login_through_the_window_creates_a_session(runtime):
    seed(runtime, "alice", PASSWORD)
    app = _make_app(runtime)
    try:
        app.login_username.insert(0, "alice")
        app.login_password.insert(0, PASSWORD)
        app._do_login()

        assert app.session_token is not None
        assert app.username == "alice"
        assert runtime.auth.current_session(app.session_token) is not None
    finally:
        app.destroy()


def test_window_shows_the_generic_message_for_bad_credentials(runtime):
    seed(runtime, "alice", PASSWORD)
    app = _make_app(runtime)
    try:
        app.login_username.insert(0, "alice")
        app.login_password.insert(0, "Definitely-Wrong-1!")
        app._do_login()

        assert app.session_token is None
        assert app.status_label is not None
        assert "Invalid username or password." in app.status_label.cget("text")
    finally:
        app.destroy()


def _all_label_text(app) -> str:
    """Concatenate every ttk.Label text in the window (for content assertions)."""
    from tkinter import ttk

    texts: list[str] = []

    def walk(widget) -> None:
        if isinstance(widget, ttk.Label):
            texts.append(str(widget.cget("text")))
        for child in widget.winfo_children():
            walk(child)

    walk(app)
    return "\n".join(texts)


def test_session_screen_greets_the_user_by_name(runtime):
    seed(runtime, "alice", PASSWORD)
    app = _make_app(runtime)
    try:
        app.login_username.insert(0, "alice")
        app.login_password.insert(0, PASSWORD)
        app._do_login()

        assert "Welcome, alice" in _all_label_text(app)
    finally:
        app.destroy()


def test_dark_mode_is_the_default_and_toggles(runtime):
    app = _make_app(runtime)
    try:
        assert app.dark_mode is True
        assert app._palette()["main_bg"] == "#212121"
        assert app._palette()["accent"] == "#10A37F"

        app.dark_var.set(False)
        app._toggle_theme()

        assert app.dark_mode is False
        assert app._palette()["main_bg"] != "#212121"
    finally:
        app.destroy()


def test_qr_helper_never_raises(runtime):
    # Optional qrcode/Pillow may be absent; the helper must degrade to None.
    app = _make_app(runtime)
    try:
        photo = gui._qr_photo("otpauth://totp/Team9:alice?secret=JBSWY3DPEHPK3PXP")
        assert photo is None or hasattr(photo, "width")
    finally:
        app.destroy()


def test_window_output_contains_no_implementer_names(runtime):
    seed(runtime, "alice", PASSWORD)
    app = _make_app(runtime)
    try:
        app.login_username.insert(0, "alice")
        app.login_password.insert(0, PASSWORD)
        app._do_login()
        text = _all_label_text(app)
        for name in ("Hazem", "Jamal", "Jennifer", "Sandeep", "Shalom"):
            assert name not in text
    finally:
        app.destroy()
