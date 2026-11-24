# Team 9 — Python-Based Password Authentication System

**Course:** CS2413  
**Project:** Design, Implementation, and Security Evaluation of a Python-Based Password Authentication System: Hashing, Policy Enforcement, and Attack Resistance  
**Repository:** https://github.com/JamalUnsal/CS2413

## Project overview

We developed a Python authentication prototype and evaluated its password-handling and account-protection controls through ten controlled experiments. The implementation includes password verification, password-policy checks, bcrypt-based credential hashing, fixed and exponential lockout strategies, TOTP multi-factor authentication (MFA), session lifecycle management, audit logging, credential-integrity checks, and JSON/SQLite storage backends.

The project is an educational prototype. Experiments use synthetic accounts and controlled local inputs; they are not intended to target real users or third-party systems.

## Project objectives

- Implement a modular password-authentication workflow.
- Compare password-hashing approaches and measure their resistance in a bounded offline dictionary experiment.
- Evaluate password-policy decisions against weak, common, username-related, medium, and strong candidates.
- Compare no lockout, fixed lockout, and exponential backoff under online guessing simulations.
- Test TOTP MFA, session expiration and invalidation, and HMAC-based tamper detection.
- Compare JSON and SQLite storage under a repeatable synthetic workload.

## Implemented security and authentication capabilities

| Area | Implementation/evaluation |
|---|---|
| Password verification | bcrypt verification and generic credential-failure messaging |
| Password policy | Minimum length, character-class checks, common-password screening, username-substring screening, and strength threshold |
| Online guessing controls | Fixed lockout and exponential backoff |
| MFA | TOTP enrollment and code verification, with failed-attempt limiting/cooldown |
| Sessions | Random session tokens, expiry, logout, and invalidate-all behavior; only token fingerprints are retained |
| Integrity | HMAC-SHA256 integrity verification for stored credential records |
| Audit | JSON Lines event logging with sensitive-field redaction |
| Storage | JSON and SQLite backends with integrity checks |

The default application password-hashing implementation uses bcrypt. Argon2id is used in the comparative hashing experiment (2).

## Repository organization

```text
CS2413/
├── auth_system/       # Authentication services, policy, MFA, sessions, lockout, audit, storage
├── experiments/       # Experiment 1 through Experiment 10
├── tests/              # Automated regression and component tests
├── tools/              # Local setup and demonstration utilities
├── docs/               # Project documentation
├── data/               # Local runtime data (do not commit secrets)
├── requirements.txt
└── README.md
```


## Requirements and setup

- Python 3.10 or newer.
- `pip`.
- Dependencies in `requirements.txt`.

```bash
git clone https://github.com/JamalUnsal/CS2413.git
cd CS2413
python -m pip install -r requirements.txt
```

If your system uses `python3`, substitute `python3` for `python`.

## Experiments and reproducibility

Run the complete experiment and test suite from the repository root:

```bash
python generate_results.py
```

To include Experiment 1, supply an existing **synthetic credential JSON** file:

```bash
python generate_results.py --credential-file data/users.json
```

The included results were generated on **2026-11-23** with the credential file at `data/users.json`. It records all ten experiments as PASS and the automated pytest suite as PASS. Experiment 1 inspected three synthetic accounts. The log reported zero plaintext passwords and zero identical password hash collisions; each inspected account had a valid salted bcrypt hash. This is evidence about the supplied test file only, not a general audit of all possible credential stores.

### Latest recorded experiment status

| Experiment | Focus | Status |
|---|---|---|
| 1 | Credential-data inspection | PASS |
| 2 | Hashing comparison | PASS |
| 3 | Password verification and enumeration behavior | PASS |
| 4 | Password-policy validation | PASS |
| 5 | Online brute-force/dictionary simulation | PASS |
| 6 | Lockout abuse and recovery | PASS |
| 7 | TOTP MFA | PASS |
| 8 | Storage-integrity tampering | PASS |
| 9 | Session lifecycle | PASS |
| 10 | JSON/SQLite comparison | PASS |

**Automated tests:** PASS. The recorded pytest output corresponds to 98 tests. Rerun the suite after changing code or dependencies:

```bash
python -m pytest -q
```

A PASS means that the experiment's programmed checks completed successfully. It does not establish that every possible attack is prevented or that the prototype is production-ready.

## Selected measured results

### Credential data inspection (Experiment 1)

- Accounts inspected: **3**.
- Plaintext passwords found: **0**.
- Identical hash collisions: **0**.
- All three inspected records were reported as valid salted bcrypt hashes.

The experiment printed only hash prefixes in its log. The result supports the conclusion that the supplied synthetic JSON file contained no detected plaintext passwords and that the three inspected accounts had distinct salted hashes.

### Password hashing (Experiment 2)

| Scheme | Mean hash time | Recovered in 2-second test window |
|---|---:|---:|
| Plaintext baseline | 0.00 ms | 70/100 |
| Unsalted MD5 | 0.04 ms | 70/100 |
| Unsalted SHA-256 | 0.01 ms | 70/100 |
| Salted SHA-256 | 0.01 ms | 70/100 |
| PBKDF2-SHA256 | 18.90 ms | 0/100 |
| bcrypt cost 8 | 14.19 ms | 0/100 |
| bcrypt cost 10 | 53.02 ms | 0/100 |
| bcrypt cost 12 | 212.00 ms | 0/100 |
| Argon2id | 34.12 ms | 0/100 |

The experiment used a fixed 100-account test set and a two-second cracking window per scheme. 

### Password policy (Experiment 4)

The policy rejected 34 of 35 weak, common, or username-related candidates (**97.1%**), exceeding the proposal's 95% target. It accepted 12 of 12 strong candidates. Overall, 39 of 55 candidates were rejected.

### Online guessing (Experiment 5)

With no lockout, the brute-force and dictionary simulations reached the correct password on the fourth attempt. Both fixed lockout and exponential backoff blocked that fourth attempt in the tested scenarios.

### Additional checks

- Experiment 3: 20/20 programmed checks passed. Generic failure messaging was observed. Median response times were 1.2 ms for an existing username and 0.9 ms for an unknown username; this small experiment does not prove the absence of a timing side channel.
- Experiment 6: fixed lockout durations were 300 seconds for both first and second lockouts; exponential backoff increased from 30 to 60 seconds. Legitimate user blocking demonstrates the availability tradeoff.
- Experiment 7: 17/17 checks passed for TOTP enrollment and verification scenarios.
- Experiment 8: 21/21 checks passed for tampering scenarios, including modified hashes and lockout fields.
- Experiment 9: 200/200 generated session tokens were unique; tokens used 256 random bits, and logout/invalidate all behavior was tested.
- Experiment 10: with 1,000 synthetic accounts, both backends completed the tested workload without concurrency errors. SQLite was faster for insertion and the concurrent update workload in this run.

## Limitations and safe-use notes

- This is a local educational prototype, not a production identity service.
- The HMAC integrity key and TOTP provisioning secrets require protected secret storage in a real deployment. Do not publish secrets, provisioning URIs, QR codes, or generated credential files.
- JSON storage rewrites the full file and is not safe for concurrent multi-process writers without an external locking strategy. SQLite provides transactional updates and stronger cross-process coordination.
- Sessions are held in memory; restarting the application invalidates active sessions.
- The password-reset demonstration does not provide a production-grade verified email or out-of-band delivery channel.
- Account lockout can temporarily deny access to legitimate users; this is an availability trade-off.
- Timing measurements are environment- and configuration dependent. The fast test configuration is not a production benchmark.

## Team responsibilities

The responsibilities below reflect the revised proposal.

| Member | Proposal-aligned responsibilities |
|---|---|
| Hazem Alfeky | Registration and password policy, password-strength screening, hashing setup; Experiments 2 and 4 |
| Sandeep Singh | Login and verification, generic errors, TOTP MFA, sessions; Experiments 3, 7, and 9 |
| Shalom Olorunfemi | Password change/reset, storage backends, HMAC integrity; Experiments 8 and 10 |
| Jamal Unsal | Lockout/backoff, audit logging, attack support; Experiments 5 and 6 |
| Jennifer Cruza | Threat-model documentation, attack simulations, Experiment 1, documentation and results consolidation |

All team members were assigned code review, testing, and presentation participation in the revised proposal.

## References

1. National Institute of Standards and Technology. *Digital Identity Guidelines: Authentication and Authenticator Management*, NIST SP 800-63B-4, 2025. https://pages.nist.gov/800-63-4/sp800-63b.html
2. OWASP Foundation. *Password Storage Cheat Sheet*. https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html
3. M'Raihi, D., Machani, S., Pei, M., & Rydell, J. *TOTP: Time-Based One-Time Password Algorithm*, RFC 6238, 2011. https://www.rfc-editor.org/rfc/rfc6238.html
4. Provos, N., & Mazières, D. *A Future-Adaptable Password Scheme* (bcrypt), USENIX Annual Technical Conference, 1999. https://www.usenix.org/legacy/events/usenix99/provos/provos.pdf
5. Biryukov, A., Dinu, D., & Khovratovich, D. *Argon2: New Generation of Memory-Hard Functions for Password Hashing and Other Applications*, IEEE European Symposium on Security and Privacy, 2016. https://www.rfc-editor.org/rfc/rfc9106.html
6. Turan, M. S., Barker, E., Burr, W., & Chen, L. *Recommendation for Password-Based Key Derivation* (PBKDF2), NIST SP 800-132, 2010. https://csrc.nist.gov/pubs/sp/800/132/final
7. Percival, C., & Josefsson, S. *The scrypt Password-Based Key Derivation Function*, RFC 7914, 2016. https://www.rfc-editor.org/rfc/rfc7914.html
8. Krawczyk, H., Bellare, M., & Canetti, R. *HMAC: Keyed-Hashing for Message Authentication*, RFC 2104, 1997. https://www.rfc-editor.org/rfc/rfc2104.html
9. Wheeler, D. *zxcvbn: Low-Budget Password Strength Estimation*, USENIX Security Symposium, 2016. https://www.usenix.org/conference/usenixsecurity16/technical-sessions/presentation/wheeler
10. Python Software Foundation. *hashlib — Secure hashes and message digests*. https://docs.python.org/3/library/hashlib.html
11. Python Software Foundation. *hmac — Keyed-Hashing for Message Authentication*. https://docs.python.org/3/library/hmac.html
12. Python Software Foundation. *secrets — Generate secure random numbers for managing secrets*. https://docs.python.org/3/library/secrets.html
13. Python Software Foundation. *base64 — Base16, Base32, Base64, Base85 Data Encodings*. https://docs.python.org/3/library/base64.html
14. Python Software Foundation. *re — Regular expression operations*. https://docs.python.org/3/library/re.html
15. Python Software Foundation. *time — Time access and conversions*. https://docs.python.org/3/library/time.html
16. Python Software Foundation. *json — JSON encoder and decoder*. https://docs.python.org/3/library/json.html
17. Python Software Foundation. *sqlite3 — DB-API 2.0 interface for SQLite databases*. https://docs.python.org/3/library/sqlite3.html
18. Python Software Foundation. *logging — Logging facility for Python*. https://docs.python.org/3/library/logging.html
19. Python Software Foundation. *tkinter — Python interface to Tcl/Tk*. https://docs.python.org/3/library/tkinter.html
20. Python Cryptographic Authority (PyCA). *bcrypt* (PyPI). https://pypi.org/project/bcrypt/
21. Schlawack, H. *argon2-cffi Documentation*. https://argon2-cffi.readthedocs.io/en/stable/
22. PyOTP Contributors. *PyOTP — The Python One-Time Password Library*. https://pyauth.github.io/pyotp/
23. Dropbox / dwolfhub. *zxcvbn-python* (PyPI). https://pypi.org/project/zxcvbn/
24. Krekel, H., et al. *pytest Documentation*. https://docs.pytest.org/
25. Matplotlib Development Team. *Matplotlib: Visualization with Python*. https://matplotlib.org/stable/
26. Lincoln, L. *qrcode* (PyPI). https://pypi.org/project/qrcode/
27. Clark, A., & Contributors. *Pillow (PIL Fork) Documentation*. https://pillow.readthedocs.io/
28. SecLists / Daniel Miessler. *RockYou Leaked Password Dataset*. https://github.com/danielmiessler/SecLists/tree/master/Passwords/Leaked-Databases
29. Supabase Inc. *Supabase Documentation*. https://supabase.com/docs
30. Real Python. *Password Hashing in Python*. https://realpython.com/python-hashlib/
31. W3Schools. *Python RegEx*. https://www.w3schools.com/python/python_regex.asp
32. W3Schools. *Matplotlib Bars*. https://www.w3schools.com/python/matplotlib_bars.asp
33. Stack Overflow. *ValueError: password cannot be longer than 72 bytes in bcrypt*. https://stackoverflow.com/questions/72551751/valueerror-password-cannot-be-longer-than-72-bytes-in-bcrypt
34. Stack Overflow. *zxcvbn very slow for long passwords*. https://stackoverflow.com/questions/44530370/zxcvbn-very-slow-for-long-passwords
35. Computerphile. *How NOT to Store Passwords*. YouTube. https://www.youtube.com/watch?v=8ZtInClXe1Q
36. Schafer, C. *Matplotlib Tutorial (Part 2): Bar Charts and Analyzing Data*. YouTube. https://www.youtube.com/watch?v=nKxLfUrkLE8
