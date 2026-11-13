"""Shared result types returned by services."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class OperationResult:
    success: bool
    message: str
    reason: str | None = None
