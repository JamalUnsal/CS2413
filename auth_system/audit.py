from __future__ import annotations

import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Mapping


class AuditEvent:
   

    REGISTRATION = "registration"
    LOGIN_SUCCESS = "login_success"
    LOGIN_FAILURE = "login_failure"
    LOCKOUT_TRIGGERED = "lockout_triggered"
    LOCKOUT_BLOCKED = "lockout_blocked"
    LOGOUT = "logout"
    SESSION_CREATED = "session_created"
    SESSION_REJECTED = "session_rejected"
    PASSWORD_CHANGE = "password_change"
    PASSWORD_RESET_REQUEST = "password_reset_request"
    PASSWORD_RESET = "password_reset"
    MFA_ENROLLMENT_STARTED = "mfa_enrollment_started"
    MFA_ENROLLMENT_CONFIRMED = "mfa_enrollment_confirmed"
    MFA_SUCCESS = "mfa_success"
    MFA_FAILURE = "mfa_failure"
    MFA_LOCKED = "mfa_locked"
    INTEGRITY_FAILURE = "integrity_failure"


@dataclass(frozen=True)
class AuditEntry:
    event: str
    username: str | None = None
    details: Mapping[str, Any] = field(default_factory=dict)
    recorded_at: float = 0.0


class AuditLog:

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)

    def record(
        self,
        event: str,
        username: str | None = None,
        details: Mapping[str, Any] | None = None,
    ) -> None:
        import json
        import sys

        def redact(value: Any) -> Any:
            if isinstance(value, Mapping):
                safe = {}
                for key, item in value.items():
                    key_text = str(key).lower()
                    sensitive = (
                        "password", "passwd", "otp", "token",
                        "secret", "credential", "hash",
                    )
                    safe[str(key)] = (
                        "[REDACTED]"
                        if any(word in key_text for word in sensitive)
                        else redact(item)
                    )
                return safe

            if isinstance(value, (list, tuple)):
                return [redact(item) for item in value]

            return value

        entry = {
            "event": str(event),
            "username": username,
            "details": redact(dict(details or {})),
            "recorded_at": time.time(),
        }

        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)

            with self.path.open("a", encoding="utf-8") as log_file:
                log_file.write(json.dumps(entry, default=str) + "\n")
                log_file.flush()

        except Exception as exc:
            print(f"Audit log write failed: {exc}", file=sys.stderr)







class NullAuditLog(AuditLog):

    def __init__(self) -> None:
        super().__init__(Path("<null>"))

    def record(
        self,
        event: str,
        username: str | None = None,
        details: Mapping[str, Any] | None = None,
    ) -> None:
        return None


class InMemoryAuditLog(AuditLog):

    def __init__(self, clock: Callable[[], float] = time.time) -> None:
        super().__init__(Path("<memory>"))
        self._clock = clock
        self.events: list[AuditEntry] = []

    def record(
        self,
        event: str,
        username: str | None = None,
        details: Mapping[str, Any] | None = None,
    ) -> None:
        self.events.append(
            AuditEntry(
                event=event,
                username=username,
                details=dict(details or {}),
                recorded_at=self._clock(),
            )
        )

    def events_for(self, event: str) -> list[AuditEntry]:
        return [entry for entry in self.events if entry.event == event]

    def clear(self) -> None:
        self.events.clear()
