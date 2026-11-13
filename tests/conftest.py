"""Shared pytest fixtures for the implemented modules."""

from __future__ import annotations

from dataclasses import replace

import pytest

from auth_system.audit import InMemoryAuditLog
from auth_system.config import Settings
from auth_system.runtime import Runtime, build_runtime
from tests.support import FakeClock


@pytest.fixture
def clock() -> FakeClock:
    return FakeClock()


@pytest.fixture
def settings(tmp_path) -> Settings:
    return replace(
        Settings(),
        data_dir=tmp_path,
        bcrypt_rounds=4,
        mfa_valid_window=0,
        mfa_max_attempts=3,
        mfa_cooldown_seconds=300,
        session_ttl_seconds=60,
        lockout_threshold=3,
    )


@pytest.fixture
def audit(clock: FakeClock) -> InMemoryAuditLog:
    return InMemoryAuditLog(clock=clock)


@pytest.fixture
def runtime(settings: Settings, clock: FakeClock, audit: InMemoryAuditLog) -> Runtime:
    instance = build_runtime(settings, audit=audit, clock=clock)
    try:
        yield instance
    finally:
        instance.close()
