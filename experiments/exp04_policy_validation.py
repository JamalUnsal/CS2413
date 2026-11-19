"""Experiment 4 - Password policy validation.

OWNER: Hazem Alfeky.

STATUS: NOT IMPLEMENTED. This file is a handoff placeholder.

Planned procedure (proposal Section 6, Experiment 4):
  * Build a test set of at least 50 passwords covering weak, common (RockYou
    subset), medium, strong and username-containing cases.
  * Run each through ``PasswordPolicy.validate_password`` at registration.
  * Report accepted/rejected counts, every rejection reason and the zxcvbn
    strength score.
  * Check the success criterion: at least 95% of weak/common passwords rejected.

Implement after ``auth_system.policy.PasswordPolicy`` is complete; this script
then only needs to load the test set and tabulate results.

Run: ``python -m experiments.exp04_policy_validation``
"""

from __future__ import annotations
from auth_system.policy import PasswordPolicy
from auth_system.config import Settings
TEST_CASES: list[tuple[str, str, str, bool]] = [
    
    ("weak", "alice", "short1!", False),
    ("weak", "alice", "alllowercase12!", False),
    ("weak", "alice", "ALLUPPERCASE12!", False),
    ("weak", "alice", "NoDigitsHere!!", False),
    ("weak", "alice", "NoSpecialChars12", False),
    ("weak", "alice", "aaaaaaaaaaaa", False),
    ("weak", "alice", "Aaaaaaaaaaa1!", False),
    ("weak", "alice", "Abcdef12345!", False),
    ("weak", "alice", "Qwertyuiopa1!", False),
    ("weak", "alice", "1234567890Aa!", False),
    ("weak", "alice", "Password1234!", False),
    ("weak", "alice", "January2025!", False),
    ("weak", "alice", "Passwords12345!", False),
    ("weak", "alice", "Iloveyou123!", False),
    ("weak", "alice", "A" * 130 + "b1!", False),

    ("common", "alice", "password", False),
    ("common", "alice", "123456", False),
    ("common", "alice", "qwerty123", False),
    ("common", "alice", "letmein123", False),
    ("common", "alice", "P@ssw0rd123!", False),
    ("common", "alice", "Passw0rd123!", False),
    ("common", "alice", "Welcome2025!", False),
    ("common", "alice", "Summer2024!", False),
    ("common", "alice", "Winter2024!", False),
    ("common", "alice", "Changeme123!", False),
    ("common", "alice", "Qwerty123!", False),
    ("common", "alice", "1qaz2wsx3edc", False),

    
    ("username", "alice", "AliceSuper99!", False),
    ("username", "alice", "MyALICEPass#22", False),
    ("username", "alice", "xX_alice_Xx99!", False),
    ("username", "hazem", "HazemSecret#88", False),
    ("username", "hazem", "99!hazem!Galaxy", False),
    ("username", "shalom", "ShalomKey2026$", False),
    ("username", "jamal", "JamalVault@77", False),
    ("username", "sandeep", "SandeepLock#44", False),

    ("medium", "alice", "P@ssw0rd!2026", False),
    ("medium", "alice", "Football#1999", False),
    ("medium", "alice", "Sunshine@2026", False),
    ("medium", "alice", "Dragon$12345", False),
    ("medium", "alice", "Shadow*98765", False),
    ("medium", "alice", "Master!2026!", False),
    ("medium", "alice", "Coffee&Bagel9", True),
    ("medium", "alice", "RiverStone#42", True),

    ("strong", "alice", "Tr0ub4dor&3!Galaxy", True),
    ("strong", "alice", "Correct-Horse-Battery-9!", True),
    ("strong", "alice", "k9#mP2$vL8@qR5!zW", True),
    ("strong", "alice", "Blueberry!Moose@749", True),
    ("strong", "alice", "Velvet-Telescope-83$", True),
    ("strong", "alice", "7gH!9pL@2xQ#5vN$8m", True),
    ("strong", "alice", "Cactus*Lantern*402!", True),
    ("strong", "alice", "Quantum#Walrus#918", True),
    ("strong", "alice", "x4!B9@nK2#wP7$dM5%", True),
    ("strong", "alice", "Copper_Falcon_617!", True),
    ("strong", "alice", "Timber!Glacier!538", True),
    ("strong", "alice", "z8$R3!tY6@hJ9#fG2%", True),
]

def main() -> int:
    policy = PasswordPolicy(Settings())
    accepted = 0
    rejected = 0
    bad_total = 0
    bad_rejected = 0

    for category, user, pw, should_accept in TEST_CASES:
        record = policy.validate_password(user, pw)
        status = "ACCEPT" if record.ok else "REJECT"
        if record.ok:
            accepted += 1
        else:
            rejected += 1

        if category in ("weak", "common", "username"):
            bad_total += 1
            if not record.ok:
                bad_rejected += 1

        reasons_txt = "; ".join(record.reasons) if record.reasons else "none"
        print(f"[{category}] {pw} -> {status} (score {record.score}/4) | {reasons_txt}")

    reject_rate = (bad_rejected / bad_total) * 100
    print(f"\nTotal: {len(TEST_CASES)} | Accepted: {accepted} | Rejected: {rejected}")
    print(f"Weak/Common/Username rejected: {bad_rejected}/{bad_total} ({reject_rate:.1f}%)")
    print(f"Criterion (>= 95.0%): {'PASS' if reject_rate >= 95.0 else 'FAIL'}")
    return 0


if __name__ == "__main__":
  raise SystemExit(main())