"""Smoke tests for the CLI login menu (owner: Sandeep Singh)."""

from __future__ import annotations

import builtins
import getpass
import json

from auth_system import cli, devtools
from auth_system.config import Settings
from auth_system.storage import create_storage

PASSWORD = "Correct-Horse-Battery-9!"


def _seed(data_dir) -> None:
    settings = Settings().with_data_dir(data_dir)
    storage = create_storage("json", settings)
    try:
        devtools.seed_user(storage, "alice", PASSWORD, rounds=4)
    finally:
        storage.close()


def test_cli_login_and_logout_flow(tmp_path, monkeypatch, capsys):
    _seed(tmp_path)
    inputs = iter(["1", "alice", "4", "5"])
    monkeypatch.setattr(builtins, "input", lambda prompt="": next(inputs))
    monkeypatch.setattr(getpass, "getpass", lambda prompt="": PASSWORD)

    exit_code = cli.main(["--data-dir", str(tmp_path)])

    output = capsys.readouterr().out
    assert exit_code == 0
    assert "Login successful." in output
    assert "Signed in as alice" in output
    assert "Logged out." in output


def test_cli_quit_without_login(tmp_path, monkeypatch):
    monkeypatch.setattr(builtins, "input", lambda prompt="": "5")

    assert cli.main(["--data-dir", str(tmp_path)]) == 0


def test_cli_refuses_tampered_storage(tmp_path, monkeypatch, capsys):
    _seed(tmp_path)
    users_path = tmp_path / "users.json"
    document = json.loads(users_path.read_text(encoding="utf-8"))
    document["users"]["alice"]["password_hash"] = "tampered"
    users_path.write_text(json.dumps(document, indent=2), encoding="utf-8")

    exit_code = cli.main(["--data-dir", str(tmp_path)])

    output = capsys.readouterr().out
    assert exit_code == 1
    assert "integrity check" in output.lower()


def test_cli_supports_sqlite_backend(tmp_path, monkeypatch):
    monkeypatch.setattr(builtins, "input", lambda prompt="": "5")

    assert cli.main(["--data-dir", str(tmp_path), "--backend", "sqlite"]) == 0


def test_cli_output_contains_no_implementer_names(tmp_path, monkeypatch, capsys):
    # Visit the registration notice ("2") then quit ("5").
    inputs = iter(["2", "5"])
    monkeypatch.setattr(builtins, "input", lambda prompt="": next(inputs))

    assert cli.main(["--data-dir", str(tmp_path)]) == 0

    output = capsys.readouterr().out
    for name in ("Hazem", "Jamal", "Jennifer", "Sandeep", "Shalom"):
        assert name not in output
