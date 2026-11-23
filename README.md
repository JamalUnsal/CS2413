# Team 9 – Password Authentication Prototype

**Course:** CS2413  
**Project topic:** Password Security and Authentication  
**Project title:** Design, Implementation, and Security Evaluation of a Python-Based Password Authentication System: Hashing, Policy Enforcement, and Attack Resistance

Team 9's project designs, implements, and evaluates a Python password-authentication prototype. The project focuses on secure password storage, password-policy enforcement, protection against online password guessing, multi-factor authentication, session handling, and detection of credential-data tampering.

The prototype is intended for educational testing in a controlled lab environment. Attack simulations use synthetic accounts and are run only against this project.

## 1. Project Objectives

The project has two connected objectives:

1. **Build a layered authentication system** that enforces password policy, stores credentials securely, limits repeated failed login attempts, supports multi-factor authentication, manages sessions, records security events, and detects unauthorized changes to stored user data.
2. **Evaluate the system's defenses** through controlled password-attack simulations and security experiments. The proposal defines measurements and success criteria so that the results can be assessed rather than assumed.

The design is organized around the confidentiality, integrity, and availability (CIA) properties of information security.

## 2. Threat Model

The project proposal identifies the following threats, controls, and security objectives.

| ID | Threat | Attack scenario | Proposed/implemented control | CIA property |
|---|---|---|---|---|
| T1 | Credential-file theft (offline attack) | An attacker obtains the stored user file and attempts to recover passwords. | Salted bcrypt password hashing; comparison with weaker hashing approaches in the evaluation. | Confidentiality |
| T2 | Online brute force | An attacker repeatedly guesses passwords through the login interface. | Failed-attempt tracking, timed lockout, and exponential backoff. | Confidentiality, Availability |
| T3 | Dictionary/common-password attack | An attacker tries likely or commonly used passwords. | Common-password blocklist, password-strength estimation, and login lockout. | Confidentiality |
| T4 | Weak password selection | A user chooses a short or predictable password. | Password-policy enforcement and strength scoring during password creation. | Confidentiality |
| T5 | User enumeration | An attacker attempts to discover valid usernames from login responses or response behavior. | Generic authentication error messages and consistent password-verification behavior. | Confidentiality |
| T6 | Data tampering | An attacker edits stored records, such as replacing a password hash or changing a lockout counter. | HMAC integrity verification of stored user data. | Integrity |
| T7 | Stolen or guessed password | An attacker knows a user's password but does not possess the user's second factor. | TOTP-based multi-factor authentication. | Confidentiality |
| T8 | Session hijacking or reuse | An attacker attempts to reuse a session token after the user has logged out or the session has expired. | Random session tokens, expiry, and logout invalidation. | Confidentiality |
| T9 | Lockout abuse (denial of service) | An attacker deliberately triggers failed logins to prevent a legitimate user from signing in. | Timed lockout and backoff rather than permanent account lockout. | Availability |

### Out-of-scope threats

The proposal excludes network-level attacks (including traffic sniffing and man-in-the-middle attacks), malware on a user's device, phishing, and attacks against the host operating system. A deployed system would require additional infrastructure protections, including TLS and appropriate endpoint and host security.

## 3. System Design and Security Controls

The prototype is written in Python and uses a local JSON file as its primary credential-storage design. The implementation also contains a SQLite storage backend. The following sections describe the security controls in the project.

### 3.1 Registration and Password Policy

The proposed policy requires passwords to:

- Contain at least 12 characters.
- Include uppercase and lowercase letters, digits, and special characters.
- Be absent from the configured common-password blocklist.
- Not contain the account username.
- Meet the configured zxcvbn password-strength threshold.

The registration and password-policy components are present in the codebase. The current CLI registration menu option is not yet connected to the registration service; demonstration accounts can be prepared for local evaluation using the seeding utility.

### 3.2 Secure Credential Storage

Passwords are stored as password hashes rather than plaintext. The implementation uses bcrypt with a per-password salt and a configurable work factor. The project also includes password-hashing and verification helpers.

The proposal calls for comparing bcrypt with weaker and alternative approaches as part of the hashing evaluation. Such comparisons should be reported only when the corresponding experiment has actually been run and its measurements recorded.

An HMAC-SHA256 integrity check is used to detect unauthorized modification of stored credential data. The integrity key is maintained separately from the JSON user data.

### 3.3 Login, Verification, and Sessions

The login workflow verifies credentials and uses generic failure messaging so that an incorrect username and an incorrect password are not disclosed through different error messages. Successful authentication can establish a session with a random token and an expiry time. Logout invalidates the session.

### 3.4 Attack Defenses

The system tracks failed login attempts and supports two lockout strategies:

- **Fixed lockout:** applies a configured timed lockout after the failure threshold is reached.
- **Exponential backoff:** increases the lockout duration as repeated failures occur, subject to a maximum delay.

A successful login resets the relevant failed-attempt and lockout state. Active lockouts are checked before additional failed attempts are counted.

### 3.5 Multi-Factor Authentication

The project uses time-based one-time passwords (TOTP) through the `pyotp` library. Users can enroll an authenticator and verify a one-time code as an additional factor when MFA is enabled. Invalid MFA attempts are subject to an attempt limit.

### 3.6 Credential Management

The project includes password-change and password-reset functionality. Password changes require verification of the existing password and validation of the replacement password. The reset workflow uses a time-limited token. The current implementation is a prototype; reset-token delivery is not an integrated, verified out-of-band service.

### 3.7 Audit Logging

The audit logger records security-related events, including authentication activity and lockout-related events. It writes JSON Lines records and redacts sensitive fields so that passwords, tokens, secrets, and hashes are not exposed in log details. Audit records can be used as supporting evidence during security experiments.

## 4. Attack Simulation Tools

The repository includes attack utilities for controlled evaluation of online password-guessing defenses. They use the project's authentication service rather than a separate mock login implementation.

### Master attack simulator

Run all supported simulator modes:

```bash
python tools/attack_simulator.py --mode all
```

Run an individual mode:

```bash
# Inspect stored credential data
python tools/attack_simulator.py --mode inspect

# Dictionary attack
python tools/attack_simulator.py --mode dictionary

# Brute-force attack
python tools/attack_simulator.py --mode brute_force
```

Example with a limited number of dictionary attempts:

```bash
python tools/attack_simulator.py \
    --mode dictionary \
    --target-user alice \
    --max-attempts 20
```

### Dictionary attack

The dictionary tool tests candidate passwords from a local wordlist, a remote wordlist source, or an embedded offline fallback list.

```bash
python tools/attack_dictionary.py \
    --target-user alice \
    --max-attempts 50
```

To provide a local wordlist:

```bash
python tools/attack_dictionary.py \
    --target-user alice \
    --wordlist path/to/wordlist.txt \
    --max-attempts 50
```

A valid local wordlist takes priority over the remote source. The tool can fall back to an embedded list when a usable local or remote list is unavailable.

### Brute-force attack

The brute-force tool generates candidate passwords using lowercase letters, uppercase letters, and digits. The maximum-attempt setting limits the number of guesses in a run.

```bash
python tools/attack_bruteforce.py \
    --target-user alice \
    --max-length 4 \
    --max-attempts 50
```

### Safe-use requirement

Run attack simulations only against the project's own local test environment or another system for which explicit authorization has been granted. Use synthetic demonstration accounts and bounded attempt limits. Do not target real accounts or third-party systems.

**Development note:** The current remote dictionary-fetch helper uses an SSL context that does not verify the remote server certificate. This is a development workaround and is not suitable for production use. Use a trusted local wordlist or restore normal certificate verification before relying on remote downloads.

## 5. Experiments and Evaluation Plan

The revised project proposal defines nine experiments. The purpose of the experiments is to collect evidence and compare measured results with the success criteria in Section 6. A proposed experiment or target is not, by itself, evidence that the experiment has been completed or that its target has been achieved.

| Experiment | Focus | Planned evaluation |
|---|---|---|
| 1. Data Inspection | Confidentiality | Inspect stored user records for plaintext or reversible passwords; check whether identical passwords produce different salted hashes. |
| 2. Hashing Algorithm Comparison | Confidentiality / offline resistance | Compare plaintext, unsalted MD5, unsalted SHA-256, salted SHA-256, PBKDF2, bcrypt, and Argon2 by hashing time and offline dictionary-attack time and success rate. Evaluate bcrypt work-factor effects. |
| 3. Password Verification | Authentication behavior | Test correct and incorrect credentials, empty and unusually long inputs, and whether responses reveal valid usernames. |
| 4. Password Policy Validation | Weak-password resistance | Test at least 50 weak, common, medium, strong, and username-containing passwords; report acceptance, rejection reasons, and strength scores. |
| 5. Online Brute-Force and Dictionary Simulation | Online guessing resistance | Compare no protection, fixed lockout, and exponential backoff. Measure guesses before blocking, total attack time, and whether the password is found. |
| 6. Lockout Abuse Test | Availability | Simulate repeated failures against a legitimate account and compare the lockout impact under fixed lockout and timed backoff. |
| 7. Multi-Factor Authentication | MFA enforcement | Test missing, incorrect, valid, and expired TOTP codes, and whether password-guessing tools can bypass the second factor. |
| 8. Integrity and Tampering Test | Integrity | Modify stored hashes or lockout fields and verify that HMAC validation detects tampering, rejects the altered data, and produces an audit event. |
| 9. Session Handling | Session security | Verify token randomness, expiry, and invalidation after logout. |

The repository currently includes credential-data inspection and attack-simulation tooling. Experiment scripts, measurements, tables, and graphs should be added or linked as they are completed. Do not infer experiment results from the presence of a tool.

### Experiment 1 – Data inspection

The repository includes a data-inspection utility:

```bash
python -m experiments.exp01_data_inspection
```

It can also be given a JSON file explicitly:

```bash
python -m experiments.exp01_data_inspection --json-file data/users.json
```

Use seeded demonstration data for the inspection. Review the script's output and retain the actual output as experiment evidence.

## 6. Success Criteria and Metrics

The proposal defines the following targets. These are evaluation targets, not claims that every target has already been achieved.

| Metric | Target defined in proposal |
|---|---|
| Plaintext passwords found in JSON storage | 0 |
| Identical passwords producing identical stored hashes | 0 (unique salts) |
| Offline dictionary attack against bcrypt compared with unsalted MD5/SHA-256 | Report both measured results; bcrypt is expected to be substantially slower to attack |
| Failed logins before lockout | Lockout at the configured threshold (example: 5) in 100% of test runs |
| Brute-force and dictionary success against a protected account | 0 successes within the attempt limit |
| Weak passwords rejected by policy | At least 95% of weak or common passwords |
| Tampering attempts detected by integrity check | 100% |
| Login attempts bypassing MFA | 0 |
| Username-enumeration differences in responses | None observable |

Report measured values, including cases where a defense falls short of its target. The final evaluation should distinguish observed results from expected behavior.

## 7. Installation and Setup

### Requirements

- Python 3.10 or newer.
- `pip`.
- Dependencies listed in `requirements.txt`.

### Clone the repository

```bash
git clone https://github.com/JamalUnsal/CS2413.git
cd CS2413
```

### Install dependencies

```bash
python -m pip install -r requirements.txt
```

If your system uses `python3` instead of `python`, substitute `python3` in the commands.

### Seed demonstration accounts

```bash
python tools/seed_demo_users.py
```

Use only the demonstration credentials generated for the local evaluation environment. Do not commit generated user records, integrity keys, or sensitive audit logs.

## 8. Running the Authentication System

Run the command-line application from the repository root:

```bash
python -m auth_system
```

The project also includes a SQLite backend. Where the CLI option is available in the current checkout, it can be selected with:

```bash
python -m auth_system --backend sqlite
```

The JSON backend is the primary storage design described in the project proposal. The SQLite backend is an additional implementation option in the codebase.

## 9. Testing

Run the automated test suite from the repository root:

```bash
python -m pytest
```

The latest test run reported by the team completed with **98 passed**. This is the result reported for the tested local code state; rerun the suite after any source-code or dependency changes.

The test suite covers authentication workflows and supporting components, including password handling, lockout behavior, audit logging, storage, integrity validation, and CLI behavior.

## 10. Project Structure

The repository is organized into authentication services, storage backends, experiments, tests, and attack tools. The following is a high-level overview; consult the repository for the complete current file tree.

```text
CS2413/
├── auth_system/
│   ├── auth.py
│   ├── audit.py
│   ├── cli.py
│   ├── config.py
│   ├── credentials.py
│   ├── lockout.py
│   ├── mfa.py
│   ├── models.py
│   ├── passwords.py
│   ├── policy.py
│   ├── registration.py
│   ├── runtime.py
│   ├── sessions.py
│   ├── verification.py
│   └── storage/
├── data/                 # Local runtime data; do not commit secrets
├── docs/
├── experiments/
├── tests/
├── tools/
│   ├── attack_simulator.py
│   ├── attack_dictionary.py
│   ├── attack_bruteforce.py
│   └── seed_demo_users.py
├── requirements.txt
└── README.md
```

## 11. Team Members and Responsibilities

The responsibilities below follow the revised project proposal.

| Team member | Responsibilities |
|---|---|
| Hazem Alfeky | Registration prompts; password complexity and blocklist validation; zxcvbn strength scoring; initial bcrypt hashing setup; hashing algorithm comparison (Experiment 2); password-policy validation (Experiment 4). |
| Sandeep Singh | Primary login menu; bcrypt verification; generic error handling against user enumeration; TOTP-based MFA; session-token handling; Experiments 3, 7, and 9. |
| Shalom Olorunfemi | Password change with old-password verification; secure reset flow; HMAC integrity protection of the JSON file; Experiment 8. |
| Jamal Unsal | Account locking, rate limiting, and exponential backoff; audit logging; assistance with attack scripts; Experiments 5 and 6. |
| Jennifer Cruza | Threat model; project documentation and final report; brute-force and dictionary attack scripts; Experiment 1; consolidation of results and graphs. |

All team members participate in code review, testing, and the final presentation.

## 12. Limitations and Ethical Considerations

This project is an educational prototype and is not intended for production deployment.

- JSON file storage does not provide the concurrency control or operational protections of a production database.
- The HMAC key and TOTP secrets require stronger secret management in a deployed system.
- The current CLI registration option is not connected to the registration service.
- Password-reset token delivery is not integrated with a verified out-of-band channel.
- The remote dictionary-fetch helper currently bypasses SSL certificate verification and should be corrected before production use.
- The prototype does not address the network, endpoint, phishing, or host-operating-system threats listed as out of scope in the proposal.

All attack simulations are restricted to the team's own system and synthetic test accounts in a controlled lab environment. No real credentials or unauthorized third-party systems are to be targeted.

## 13. Project Deliverables

The revised proposal identifies the following expected deliverables:

1. Python source code for the authentication system, attack scripts, and hashing-comparison harness.
2. A written threat model mapping threats to controls and CIA properties.
3. Experiment results with tables and graphs evaluated against the stated success criteria.
4. A final report describing design decisions, findings, limitations, and recommendations.
5. A final presentation demonstrating login, lockout, MFA, and tamper-detection experiments.

The README documents the project and provides entry points to the code and evaluation workflow. The detailed threat/security analysis and full experiment findings should remain separate project deliverables.

## Project Information

- **Course:** CS2413
- **Team:** 9
- **Project topic:** Password Security and Authentication
- **Repository:** https://github.com/JamalUnsal/CS2413
- **Environment:** Controlled educational lab using synthetic test accounts
