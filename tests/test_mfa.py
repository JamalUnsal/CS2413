"""Unit tests for TOTP MFA (owner: Sandeep Singh)."""

from __future__ import annotations

from dataclasses import replace

from auth_system.config import Settings
from auth_system.mfa import MfaService
from tests.support import FakeClock

USERNAME = "alice"


def make_service(clock: FakeClock, **overrides) -> MfaService:
    settings = replace(Settings(), **overrides)
    return MfaService(settings, clock=clock)


def test_enrollment_produces_secret_and_uri(clock: FakeClock):
    service = make_service(clock)
    enrollment = service.enrollment_for(USERNAME)

    assert len(enrollment.secret) >= 16
    assert enrollment.provisioning_uri.startswith("otpauth://totp/")
    assert USERNAME in enrollment.provisioning_uri
    assert "Team9-AuthPrototype" in enrollment.provisioning_uri


def test_current_code_is_accepted(clock: FakeClock):
    service = make_service(clock)
    enrollment = service.enrollment_for(USERNAME)
    code = service.generate_code(enrollment.secret)

    assert service.verify_code(enrollment.secret, code) is True


def test_wrong_code_is_rejected(clock: FakeClock):
    service = make_service(clock)
    enrollment = service.enrollment_for(USERNAME)
    code = service.generate_code(enrollment.secret, at=clock.now + 120)

    assert service.verify_code(enrollment.secret, code) is False


def test_code_window_setting_is_respected(clock: FakeClock):
    strict = make_service(clock, mfa_valid_window=0)
    tolerant = make_service(clock, mfa_valid_window=1)
    secret = strict.enrollment_for(USERNAME).secret
    previous_code = strict.generate_code(secret, at=clock.now - 30)

    assert strict.verify_code(secret, previous_code) is False
    assert tolerant.verify_code(secret, previous_code) is True


def test_malformed_codes_are_rejected(clock: FakeClock):
    service = make_service(clock)
    secret = service.enrollment_for(USERNAME).secret

    assert service.verify_code(secret, "") is False
    assert service.verify_code(secret, "abcdef") is False
    assert service.verify_code(secret, "12345") is False
    assert service.verify_code(secret, None) is False
    assert service.verify_code("", service.generate_code(secret)) is False
    assert service.verify_code("not-base32!", "123456") is False


def test_code_separators_are_normalised(clock: FakeClock):
    service = make_service(clock)
    secret = service.enrollment_for(USERNAME).secret
    code = service.generate_code(secret)
    spaced = f"{code[:3]} {code[3:]}"

    assert service.normalize_code(spaced) == code
    assert service.verify_code(secret, spaced) is True
