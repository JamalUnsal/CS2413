"""Shared helpers for experiment scripts (tables, checks, clocks, fixtures)."""

from __future__ import annotations

import time
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Callable, Iterable, Sequence

from auth_system import devtools
from auth_system.audit import InMemoryAuditLog
from auth_system.config import Settings
from auth_system.models import UserRecord
from auth_system.runtime import Runtime, build_runtime

from auth_system.lockout import NoLockoutPolicy


class ExperimentClock:
    """Controllable clock so time-based behaviour can be tested without sleeps."""

    def __init__(self, now: float = 1_700_000_000.0) -> None:
        self.now = now

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


def make_settings(directory: str | Path, **overrides: object) -> Settings:
    """Experiment defaults: low bcrypt cost for speed and deterministic MFA."""
    base = Settings().with_data_dir(Path(directory))
    base = replace(
        base,
        bcrypt_rounds=4,
        mfa_valid_window=0,
        mfa_max_attempts=3,
        mfa_cooldown_seconds=300,
        session_ttl_seconds=600,
        lockout_threshold=3,
    )
    return replace(base, **overrides)


def make_runtime(
    directory: str | Path,
    *,
    backend: str = "json",
    clock: Callable[[], float] = time.time,
    audit: object | None = None,
    **overrides: object,
) -> Runtime:
    settings = make_settings(directory, **overrides)
    audit_log = audit if audit is not None else InMemoryAuditLog(clock=clock)
    return build_runtime(settings, backend=backend, audit=audit_log, lockout=NoLockoutPolicy(), clock=clock)


def seed(
    runtime: Runtime,
    username: str,
    password: str,
    **kwargs: object,
) -> UserRecord:
    return devtools.seed_user(
        runtime.storage,
        username,
        password,
        rounds=runtime.settings.bcrypt_rounds,
        clock=runtime.clock,
        **kwargs,
    )


def text_table(headers: Sequence[str], rows: Iterable[Sequence[object]]) -> str:
    string_rows = [[str(cell) for cell in row] for row in rows]
    widths = [len(header) for header in headers]
    for row in string_rows:
        for index, cell in enumerate(row):
            widths[index] = max(widths[index], len(cell))

    def render(row: Sequence[str]) -> str:
        return "| " + " | ".join(cell.ljust(widths[i]) for i, cell in enumerate(row)) + " |"

    separator = "+" + "+".join("-" * (width + 2) for width in widths) + "+"
    lines = [separator, render(headers), separator]
    lines.extend(render(row) for row in string_rows)
    lines.append(separator)
    return "\n".join(lines)


@dataclass
class Check:
    name: str
    passed: bool
    detail: str


class Report:
    """Collects pass/fail checks and prints a consistent experiment summary."""

    def __init__(self, title: str, subtitle: str = "") -> None:
        self.title = title
        self.subtitle = subtitle
        self.checks: list[Check] = []
        self.notes: list[str] = []

    def check(self, name: str, passed: bool, detail: str = "") -> bool:
        self.checks.append(Check(name, bool(passed), detail))
        return bool(passed)

    def note(self, text: str) -> None:
        self.notes.append(text)

    @property
    def ok(self) -> bool:
        return all(item.passed for item in self.checks)

    def render(self) -> str:
        lines = [self.title, "=" * len(self.title)]
        if self.subtitle:
            lines.extend([self.subtitle, ""])
        lines.append(
            text_table(
                ("Check", "Result", "Detail"),
                [(item.name, "PASS" if item.passed else "FAIL", item.detail) for item in self.checks],
            )
        )
        if self.notes:
            lines.append("")
            lines.append("Notes:")
            lines.extend(f"  - {note}" for note in self.notes)
        passed = sum(1 for item in self.checks if item.passed)
        lines.extend(["", f"RESULT: {passed}/{len(self.checks)} checks passed"])
        return "\n".join(lines)

    def finish(self) -> int:
        print(self.render())
        return 0 if self.ok else 1
