"""Unit tests for bcrypt verification (owner: Sandeep Singh)."""

from __future__ import annotations

from auth_system import devtools
from auth_system.verification import (
    INVALID_CREDENTIALS_MESSAGE,
    dummy_hash_for,
    dummy_verify,
    verify_password,
)

PASSWORD = "Correct-Horse-Battery-9!"


def test_correct_password_verifies():
    stored = devtools.dev_hash_password(PASSWORD, rounds=4)
    assert verify_password(stored, PASSWORD) is True


def test_wrong_password_is_rejected():
    stored = devtools.dev_hash_password(PASSWORD, rounds=4)
    assert verify_password(stored, "Wrong-Password-1!") is False


def test_long_passwords_are_not_truncated():
    long_password = "x" * 200 + "-A"
    same_prefix_different_tail = "x" * 200 + "-B"
    stored = devtools.dev_hash_password(long_password, rounds=4)

    assert verify_password(stored, long_password) is True
    assert verify_password(stored, same_prefix_different_tail) is False


def test_malformed_hashes_return_false_without_raising():
    assert verify_password("", PASSWORD) is False
    assert verify_password("not-a-bcrypt-hash", PASSWORD) is False
    assert verify_password(None, PASSWORD) is False  # type: ignore[arg-type]


def test_non_string_password_returns_false():
    stored = devtools.dev_hash_password(PASSWORD, rounds=4)
    assert verify_password(stored, None) is False  # type: ignore[arg-type]


def test_dummy_verify_handles_extreme_inputs():
    dummy_verify("")
    dummy_verify("A" * 10_000)
    dummy_verify(None)  # type: ignore[arg-type]


def test_dummy_hash_matches_requested_work_factor():
    for rounds in (4, 12):
        assert dummy_hash_for(rounds).split("$")[2] == f"{rounds:02d}"


def test_generic_message_is_stable():
    assert INVALID_CREDENTIALS_MESSAGE == "Invalid username or password."
