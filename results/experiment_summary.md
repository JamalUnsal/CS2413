# CS2413 Project - Experiment and Test Results

Generated (UTC): 2026-11-23T23:12:10.883313+00:00

## Experiment execution summary

| Experiment | Result | Runtime (s) | Log |
|---|---:|---:|---|
| Experiment 1 - Credential data inspection | **PASS** | 0.089 | `results/logs/exp01_data_inspection.log` |
| Experiment 2 - Hashing comparison | **PASS** | 44.052 | `results/logs/exp02_hashing_comparison.log` |
| Experiment 3 - Password verification | **PASS** | 0.111 | `results/logs/exp03_password_verification.log` |
| Experiment 4 - Password policy validation | **PASS** | 0.081 | `results/logs/exp04_policy_validation.log` |
| Experiment 5 - Online attack simulation | **PASS** | 0.098 | `results/logs/exp05_online_attack.log` |
| Experiment 6 - Lockout abuse and availability | **PASS** | 0.075 | `results/logs/exp06_lockout_abuse.log` |
| Experiment 7 - Multi-factor authentication | **PASS** | 0.078 | `results/logs/exp07_mfa.log` |
| Experiment 8 - Integrity and tampering | **PASS** | 0.077 | `results/logs/exp08_integrity_tampering.log` |
| Experiment 9 - Session security | **PASS** | 0.065 | `results/logs/exp09_sessions.log` |
| Experiment 10 - Storage comparison | **PASS** | 5.251 | `results/logs/exp10_storage_comparison.log` |

## Automated tests

- **Result:** PASS
- **Runtime:** 2.754 seconds
- **Log:** `results/logs/pytest.log`

## Generated graphs

- `results/graphs/hashing_time.png`
- `results/graphs/dictionary_crack_results.png`
- `results/graphs/password_policy_results.png`
- `results/graphs/online_attack_attempts.png`
- `results/graphs/lockout_duration_comparison.png`
- `results/graphs/storage_insert_time_s.png`
- `results/graphs/storage_single_read_ms.png`
- `results/graphs/storage_list_all_time_s.png`
- `results/graphs/storage_concurrent_updates_s.png`

## Interpretation and reporting notes

- A **PASS** means the experiment process returned exit code 0; consult its log for the individual checks and measured values.
- A **FAIL**, **ERROR**, or **TIMEOUT** must be investigated before reporting the experiment as successful.
- Experiment 1 is skipped unless an existing credential JSON file is supplied with `--credential-file`. This prevents the experiment's fallback mock database from being used as project evidence.
- The hashing experiment's dictionary-attack results use its own fixed test set and time limit. They should not be generalized to all passwords or attackers.
- The online attack experiment is a controlled local simulation using three incorrect guesses followed by the correct password, not a real-world attack benchmark.
- MFA, session, integrity, and other functional checks are retained in their individual logs; present these primarily as test-result tables rather than inventing numerical graphs.
- Graphs are generated only from values printed by the experiment scripts. If a parser cannot find a table or measurement, it does not fabricate replacement data.
- Include the relevant graphs and interpretation in the final report, and retain the `results/logs/` and `results/raw/` files as supporting evidence.

## Re-running

Run `python generate_results.py` from the repository root. To include Experiment 1, provide an existing credential JSON file: `python generate_results.py --credential-file data/users.json`.
