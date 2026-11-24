from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from types import TracebackType

from auth_system.models import UserRecord


@dataclass(frozen=True)
class IntegrityReport:
    backend: str
    ok: bool
    checked_records: int
    problems: tuple[str, ...] = ()

    def describe(self) -> str:
        if self.ok:
            return (
                f"{self.backend}: integrity OK "
                f"({self.checked_records} record(s) verified)"
            )
        joined = "; ".join(self.problems) if self.problems else "unknown problem"
        return f"{self.backend}: INTEGRITY FAILURE - {joined}"


class StorageBackend(ABC):
    """Replaceable user-record store."""

    backend_name: str = "abstract"

    @abstractmethod
    def get_user(self, username: str) -> UserRecord | None:
        """Return a copy of the record for ``username`` or ``None``."""

    @abstractmethod
    def save_user(self, user: UserRecord) -> None:
        """Insert or update ``user`` (also refreshes any integrity data)."""

    @abstractmethod
    def list_users(self) -> list[UserRecord]:
        """Return copies of every stored record."""

    @abstractmethod
    def delete_user(self, username: str) -> bool:
        """Delete ``username``; return ``True`` when a record was removed."""

    @abstractmethod
    def verify_integrity(self) -> IntegrityReport:
        """Check the integrity of the persisted data without raising."""

    @abstractmethod
    def close(self) -> None:
        """Release resources (idempotent)."""

    # -- convenience -----------------------------------------------------
    def user_exists(self, username: str) -> bool:
        return self.get_user(username) is not None

    def __enter__(self) -> "StorageBackend":
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        self.close()
