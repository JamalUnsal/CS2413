# Threat model (PLACEHOLDER)

OWNER: **Jennifer Cruza**.

STATUS: **NOT IMPLEMENTED** - this file is a handoff outline. Expand it into the
written threat-model deliverable using Section 4 of the approved proposal.

## Required content

1. Scope and assumptions (CLI prototype, synthetic accounts, lab environment;
   out of scope: network sniffing/MITM, malware, phishing, host compromise).
2. Threat table with columns: `#`, threat, attack description, control, CIA
   property, implementation reference, experiment/evidence.
3. Attack surface and trust boundaries (CLI input, JSON/SQLite store, HMAC key
   file, session store, TOTP device).
4. Residual risks and mitigation notes (prototype limitations from the README).

## Threat rows to carry over from the proposal

T1 credential file theft (offline) - salted bcrypt - confidentiality
T2 online brute force - failure counter / lockout / backoff - availability, confidentiality
T3 dictionary / common-password attack - blocklist, strength, lockout - confidentiality
T4 weak password selection - policy + strength scoring - confidentiality
T5 user enumeration - generic messages, dummy bcrypt cost - confidentiality
T6 data tampering - HMAC integrity check - integrity
T7 stolen/guessed password - TOTP MFA - confidentiality
T8 session hijacking/reuse - random tokens, expiry, logout invalidation - confidentiality
T9 lockout abuse (DoS) - timed lockout/backoff, no permanent lockout - availability

Map each control to the owning module and the experiment that measures it
(see `docs/OWNERSHIP.md` and `experiments/`). Mark controls whose module is
still a placeholder.
