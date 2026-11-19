#Owner: Jamal Unsal
from auth_system.lockout import (
    ExponentialBackoffPolicy,
    FixedLockoutPolicy,
)
from auth_system.models import UserRecord


def test_fixed_lockout_starts_at_threshold():
    policy = FixedLockoutPolicy(threshold=3, lockout_seconds=300)
    user = UserRecord(username="alice")

    assert policy.register_failure(user, 1000).allowed
    assert policy.register_failure(user, 1000).allowed

    decision = policy.register_failure(user, 1000)

    assert decision.locked
    assert not decision.allowed
    assert decision.retry_after == 300
    assert user.lockout_until == 1300


def test_fixed_lockout_blocks_until_expiration():
    policy = FixedLockoutPolicy(threshold=2, lockout_seconds=60)
    user = UserRecord(username="alice")

    policy.register_failure(user, 1000)
    policy.register_failure(user, 1000)

    assert not policy.check(user, 1050).allowed
    assert policy.check(user, 1061).allowed


def test_exponential_backoff_doubles_delay():
    policy = ExponentialBackoffPolicy(
        threshold=2,
        base_seconds=30,
        max_seconds=120,
    )
    user = UserRecord(username="alice")

    policy.register_failure(user, 1000)
    first = policy.register_failure(user, 1000)
    assert first.retry_after == 30

    policy.register_failure(user, 1031)
    second = policy.register_failure(user, 1031)
    assert second.retry_after == 60

    policy.register_failure(user, 1092)
    third = policy.register_failure(user, 1092)
    assert third.retry_after == 120


def test_exponential_backoff_respects_maximum():
    policy = ExponentialBackoffPolicy(
        threshold=1,
        base_seconds=30,
        max_seconds=60,
    )
    user = UserRecord(username="alice")

    assert policy.register_failure(user, 1000).retry_after == 30
    assert policy.register_failure(user, 1031).retry_after == 60
    assert policy.register_failure(user, 1092).retry_after == 60


def test_successful_login_reset_clears_lockout_state():
    policy = FixedLockoutPolicy(threshold=2, lockout_seconds=60)
    user = UserRecord(username="alice")

    policy.register_failure(user, 1000)
    policy.register_failure(user, 1000)

    policy.reset(user, 1061)

    assert user.failed_attempts == 0
    assert user.lockout_until is None
    assert policy.check(user, 1061).allowed
