"""Central configuration for the authentication prototype.

Every module reads its tunable knobs from this object instead of hard-coding
them, so experiments can override values (lockout strategy, work factor,
session lifetime, ...) without editing library code.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from pathlib import Path


@dataclass(frozen=True)
class Settings:
    # --- storage (owner: Shalom Olorunfemi) ---------------------------------
    data_dir: Path = Path("data")
    users_file_name: str = "users.json"
    sqlite_file_name: str = "users.db"
    integrity_key_file_name: str = "integrity.key"
    audit_log_file_name: str = "audit.log"

    # --- password hashing (owner: Hazem Alfeky) -----------------------------
    bcrypt_rounds: int = 12

    # --- password policy (owner: Hazem Alfeky) ------------------------------
    password_min_length: int = 12
    password_max_length: int = 128
    password_min_strength: int = 3  # zxcvbn score 0..4
    blocklist_file_name: str = "blocklist.txt"

    # --- lockout / rate limiting (owner: Jamal Unsal) -----------------------
    lockout_threshold: int = 5
    fixed_lockout_seconds: int = 300
    backoff_base_seconds: int = 30
    backoff_max_seconds: int = 3600

    # --- sessions (owner: Sandeep Singh) ------------------------------------
    session_ttl_seconds: int = 1800
    session_token_bytes: int = 32

    # --- multi-factor authentication (owner: Sandeep Singh) -----------------
    mfa_issuer: str = "Team9-AuthPrototype"
    mfa_digits: int = 6
    mfa_interval_seconds: int = 30
    mfa_valid_window: int = 1
    mfa_max_attempts: int = 5
    mfa_cooldown_seconds: int = 300

    # --- password reset (owner: Shalom Olorunfemi) --------------------------
    reset_token_ttl_seconds: int = 900

    # ------------------------------------------------------------------------
    # Derived paths
    # ------------------------------------------------------------------------
    @property
    def users_path(self) -> Path:
        return self.data_dir / self.users_file_name

    @property
    def sqlite_path(self) -> Path:
        return self.data_dir / self.sqlite_file_name

    @property
    def integrity_key_path(self) -> Path:
        return self.data_dir / self.integrity_key_file_name

    @property
    def audit_log_path(self) -> Path:
        return self.data_dir / self.audit_log_file_name

    @property
    def blocklist_path(self) -> Path:
        return self.data_dir / self.blocklist_file_name

    def with_data_dir(self, path: str | Path) -> "Settings":
        return replace(self, data_dir=Path(path))


DEFAULT_SETTINGS = Settings()
