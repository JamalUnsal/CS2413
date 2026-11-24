"""Password policy and strength estimation.
``validate_password(username, password) -> PolicyResult``
    * minimum length from ``Settings.password_min_length`` (12);
    * maximum length from ``Settings.password_max_length`` (128) to bound work;
    * at least one upper-case letter, one lower-case letter, one digit and one
      special character;
    * reject entries in ``Settings.blocklist_path`` (loaded once, lower-cased);
    * reject passwords containing the username (case-insensitive);
    * reject a zxcvbn score below ``Settings.password_min_strength`` (3);
    * return *all* failed reasons, not just the first, and never raise for a
      merely weak password.

``strength(password) -> PolicyResult``
    * zxcvbn score in ``score`` and its warning/suggestions in ``feedback``;
      use it in the registration prompt to guide the user.
"""

from __future__ import annotations
from dataclasses import dataclass
from auth_system.config import Settings
from pathlib import Path
from zxcvbn import zxcvbn


@dataclass(frozen=True)
class PolicyResult:
    ok: bool
    reasons: tuple[str, ...] = ()
    score: int | None = None
    feedback: tuple[str, ...] = ()

    def summary(self) -> str:
        if self.ok:
            return "Password accepted."
        return " ".join(self.reasons) if self.reasons else "Password rejected."


class PasswordPolicy:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self.blocklist: frozenset[str] | None = None

    def load_blocklist(self) -> frozenset[str]:
        if self.blocklist is None:
            lines = Path(self.settings.blocklist_path).read_text(encoding="utf-8").splitlines()
            self.blocklist = frozenset(line.strip().lower() for line in lines if line.strip() and not line.startswith("#"))
        return self.blocklist
    
    def strength(self, password: str) -> PolicyResult:
        report = zxcvbn(password[:72]) # zxcvbn max is 72, otherwise it causes an error
        notes = report["feedback"]
        hints = tuple(item for item in [notes.get("warning"), *notes.get("suggestions", [])] if item)
        return PolicyResult(
            ok=report["score"] >= self.settings.password_min_strength,
            score=report["score"],  
            feedback=hints,
        )

    def validate_password(self, username: str, password: str) -> PolicyResult:
        issues = []
        if len(password) < self.settings.password_min_length:
            issues.append(f"Password must be at least {self.settings.password_min_length} characters long.")
        if len(password) > self.settings.password_max_length:
            issues.append(f"Password must be no more than {self.settings.password_max_length} characters long.")
        if not any(c.isupper() for c in password):
            issues.append("Password must contain at least one uppercase letter.")
        if not any(c.islower() for c in password):
            issues.append("Password must contain at least one lowercase letter.")
        if not any(c.isdigit() for c in password):
            issues.append("Password must contain at least one digit.")
        if not any(c in "!@#$%^&*()-+" for c in password):
            issues.append("Password must contain at least one special character.")
        if username.lower() in password.lower():
            issues.append("Password must not contain the username.")
        if password.lower() in self.load_blocklist():
            issues.append("Password is in the common-password blocklist.")

        check = self.strength(password)
        if check.score < self.settings.password_min_strength:
            issues.append(f"Strength score {check.score}/4 is below {self.settings.password_min_strength}/4.")

        return PolicyResult(
            ok=len(issues) == 0,
            reasons=tuple(issues),
            score=check.score,
            feedback=check.feedback,
        )

    
