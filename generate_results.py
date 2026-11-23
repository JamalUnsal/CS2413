#!/usr/bin/env python3
"""
CS2413 Team 9 - Experiment and test results collector.

Run from the repository root:
    python generate_results.py
    python generate_results.py --credential-file data/users.json
    python generate_results.py --skip-tests

The collector runs the experiment modules, captures their original output, and
creates a results/ folder containing logs, machine-readable run metadata,
a Markdown summary, and charts derived from the experiments' printed results.

Experiment 1 is deliberately skipped unless --credential-file points to an
existing credential JSON file. This avoids exp01's built-in mock-database
creation being mistaken for real project evidence.
"""
from __future__ import annotations

import argparse
import csv
import json
import re
import shutil
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent

EXPERIMENTS = [
    ("exp01_data_inspection", "Experiment 1 - Credential data inspection"),
    ("exp02_hashing_comparison", "Experiment 2 - Hashing comparison"),
    ("exp03_password_verification", "Experiment 3 - Password verification"),
    ("exp04_policy_validation", "Experiment 4 - Password policy validation"),
    ("exp05_online_attack", "Experiment 5 - Online attack simulation"),
    ("exp06_lockout_abuse", "Experiment 6 - Lockout abuse and availability"),
    ("exp07_mfa", "Experiment 7 - Multi-factor authentication"),
    ("exp08_integrity_tampering", "Experiment 8 - Integrity and tampering"),
    ("exp09_sessions", "Experiment 9 - Session security"),
    ("exp10_storage_comparison", "Experiment 10 - Storage comparison"),
]


def run_command(command: list[str], log_path: Path, timeout: int = 900) -> dict:
    started = time.perf_counter()
    try:
        completed = subprocess.run(
            command, cwd=ROOT, text=True, stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT, timeout=timeout, check=False,
        )
        output = completed.stdout or ""
        code = completed.returncode
        status = "PASS" if code == 0 else "FAIL"
        error = ""
    except subprocess.TimeoutExpired as exc:
        output = (exc.stdout or "")
        if isinstance(output, bytes):
            output = output.decode("utf-8", errors="replace")
        output += f"\n\nTIMED OUT after {timeout} seconds.\n"
        code = None
        status = "TIMEOUT"
        error = f"Exceeded {timeout} seconds"
    except Exception as exc:  # preserve a useful log if process launch fails
        output = f"Could not run command: {type(exc).__name__}: {exc}\n"
        code = None
        status = "ERROR"
        error = str(exc)

    elapsed = time.perf_counter() - started
    log_path.parent.mkdir(parents=True, exist_ok=True)
    log_path.write_text(output, encoding="utf-8")
    return {
        "status": status,
        "return_code": code,
        "elapsed_seconds": round(elapsed, 3),
        "command": command,
        "log": str(log_path.relative_to(ROOT)),
        "error": error,
        "output": output,
    }


def parse_pipe_table(output: str, expected_first_cell: str) -> list[list[str]]:
    """Read the simple ASCII tables emitted by experiments/_common.py."""
    rows = []
    for line in output.splitlines():
        stripped = line.strip()
        if not stripped.startswith("|") or not stripped.endswith("|"):
            continue
        cells = [cell.strip() for cell in stripped.strip("|").split("|")]
        if cells and cells[0].lower() == expected_first_cell.lower():
            continue
        if cells and cells[0] and not set("+- ").issuperset(set(cells[0])):
            rows.append(cells)
    return rows


def make_charts(results_dir: Path, outputs: dict[str, str]) -> list[str]:
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except Exception as exc:
        (results_dir / "graphs" / "CHARTS_NOT_GENERATED.txt").write_text(
            "Charts were not generated because matplotlib could not be imported.\n"
            f"Details: {exc}\nInstall project requirements and rerun the collector.\n",
            encoding="utf-8",
        )
        return []

    graph_dir = results_dir / "graphs"
    graph_dir.mkdir(parents=True, exist_ok=True)
    created: list[str] = []

    # Exp 2: values are printed by the actual hashing experiment.
    hash_rows = []
    pattern = re.compile(
        r"^\[([a-zA-Z0-9_]+)\]\s+hash_time=([0-9.]+)\s+ms\s+\|\s+"
        r"cracked=(\d+)/100\s+in\s+([0-9.]+)s",
        re.MULTILINE,
    )
    for name, hash_ms, cracked, elapsed in pattern.findall(
        outputs.get("exp02_hashing_comparison", "")
    ):
        hash_rows.append((name, float(hash_ms), int(cracked), float(elapsed)))

    if hash_rows:
        names = [row[0] for row in hash_rows]
        times = [row[1] for row in hash_rows]
        plt.figure(figsize=(10, 5))
        plt.barh(names, times)
        plt.xlabel("Time to calculate one hash (milliseconds)")
        plt.title("Password Hashing Time by Scheme")
        plt.tight_layout()
        path = graph_dir / "hashing_time.png"
        plt.savefig(path, dpi=160)
        plt.close()
        created.append(str(path.relative_to(ROOT)))

        cracked = [row[2] for row in hash_rows]
        plt.figure(figsize=(10, 5))
        plt.barh(names, cracked)
        plt.xlabel("Accounts cracked within the experiment's dictionary/time limit (out of 100)")
        plt.title("Offline Dictionary Attack Results by Hashing Scheme")
        plt.xlim(0, 100)
        plt.tight_layout()
        path = graph_dir / "dictionary_crack_results.png"
        plt.savefig(path, dpi=160)
        plt.close()
        created.append(str(path.relative_to(ROOT)))

        with (results_dir / "raw" / "hashing_results.csv").open(
            "w", newline="", encoding="utf-8"
        ) as handle:
            writer = csv.writer(handle)
            writer.writerow(["scheme", "hash_time_ms", "accounts_cracked_out_of_100",
                             "attack_elapsed_seconds"])
            writer.writerows(hash_rows)

    # Exp 4: aggregate the exact per-case ACCEPT/REJECT lines by test category.
    policy_counts: dict[str, list[int]] = {}
    policy_pattern = re.compile(r"^\[(weak|common|username|medium|strong)\].* -> (ACCEPT|REJECT)",
                                re.MULTILINE)
    for category, status in policy_pattern.findall(outputs.get("exp04_policy_validation", "")):
        counts = policy_counts.setdefault(category, [0, 0])  # accepted, rejected
        counts[0 if status == "ACCEPT" else 1] += 1
    if policy_counts:
        categories = list(policy_counts)
        accepted = [policy_counts[c][0] for c in categories]
        rejected = [policy_counts[c][1] for c in categories]
        positions = list(range(len(categories)))
        plt.figure(figsize=(8, 5))
        plt.bar(positions, accepted, label="Accepted")
        plt.bar(positions, rejected, bottom=accepted, label="Rejected")
        plt.xticks(positions, categories)
        plt.ylabel("Number of test passwords")
        plt.title("Password Policy Decisions by Test Category")
        plt.legend()
        plt.tight_layout()
        path = graph_dir / "password_policy_results.png"
        plt.savefig(path, dpi=160)
        plt.close()
        created.append(str(path.relative_to(ROOT)))
        with (results_dir / "raw" / "policy_results.csv").open(
            "w", newline="", encoding="utf-8"
        ) as handle:
            writer = csv.writer(handle)
            writer.writerow(["category", "accepted", "rejected", "total"])
            for category, (yes, no) in policy_counts.items():
                writer.writerow([category, yes, no, yes + no])

    # Exp 5: attack attempts by protection strategy.
    attack_rows = parse_pipe_table(outputs.get("exp05_online_attack", ""), "Attack")
    if attack_rows:
        labels, attempts = [], []
        for row in attack_rows:
            if len(row) < 3:
                continue

            try:
                attempt_count = float(row[2])
            except (ValueError, TypeError):
                continue

            # Add the label and value together only after validation.
            labels.append(f"{row[0]}\n{row[1]}")
            attempts.append(attempt_count)
        if labels:
            plt.figure(figsize=(9, 5))
            plt.bar(range(len(labels)), attempts)
            plt.xticks(range(len(labels)), labels, rotation=25, ha="right")
            plt.ylabel("Login attempts before stopping")
            plt.title("Online Attack Attempts by Protection Strategy")
            plt.tight_layout()
            path = graph_dir / "online_attack_attempts.png"
            plt.savefig(path, dpi=160)
            plt.close()
            created.append(str(path.relative_to(ROOT)))

    # Exp 6: first and second lockout durations.
        # Exp 6: first and second lockout durations.
    lockout_rows = parse_pipe_table(
        outputs.get("exp06_lockout_abuse", ""),
        "Strategy"
    )

    labels, first, second = [], [], []

    for row in lockout_rows:
        if len(row) < 3:
            continue

        first_match = re.search(r"\d+(?:\.\d+)?", row[1])
        second_match = re.search(r"\d+(?:\.\d+)?", row[2])

        if not first_match or not second_match:
            continue

        # Only append a row when BOTH numeric values are available.
        labels.append(row[0])
        first.append(float(first_match.group()))
        second.append(float(second_match.group()))

    if labels and len(labels) == len(first) == len(second):
        x = list(range(len(labels)))
        width = 0.35

        plt.figure(figsize=(8, 5))
        plt.bar(
            [i - width / 2 for i in x],
            first,
            width,
            label="First lockout"
        )
        plt.bar(
            [i + width / 2 for i in x],
            second,
            width,
            label="Second lockout"
        )

        plt.xticks(x, labels)
        plt.ylabel("Lockout duration (seconds)")
        plt.title("Fixed Lockout vs Exponential Backoff")
        plt.legend()
        plt.tight_layout()

        path = graph_dir / "lockout_duration_comparison.png"
        plt.savefig(path, dpi=160)
        plt.close()

        created.append(str(path.relative_to(ROOT)))
    else:
        print(
            "Skipping Experiment 6 chart: "
            f"inconsistent or missing data "
            f"(labels={len(labels)}, first={len(first)}, "
            f"second={len(second)})."
        )

    # Exp 10: JSON and SQLite storage timings from the experiment's own table.
    storage_rows = parse_pipe_table(outputs.get("exp10_storage_comparison", ""), "Backend")
    if storage_rows:
        labels, insert, read, listing, concurrent = [], [], [], [], []
        for row in storage_rows:
            if len(row) >= 7:
                try:
                    labels.append(row[0])
                    insert.append(float(row[1]))
                    read.append(float(row[2]))
                    listing.append(float(row[3]))
                    concurrent.append(float(row[4]))
                except ValueError:
                    pass
        if labels:
            metrics = [
                ("Insert time (s)", insert),
                ("Single read (ms)", read),
                ("List all time (s)", listing),
                ("Concurrent updates (s)", concurrent),
            ]
            for metric, values in metrics:
                plt.figure(figsize=(6, 4))
                plt.bar(labels, values)
                plt.ylabel(metric)
                plt.title(f"JSON vs SQLite: {metric}")
                plt.tight_layout()
                filename = re.sub(r"[^a-z0-9]+", "_", metric.lower()).strip("_")
                path = graph_dir / f"storage_{filename}.png"
                plt.savefig(path, dpi=160)
                plt.close()
                created.append(str(path.relative_to(ROOT)))

            with (results_dir / "raw" / "storage_results.csv").open(
                "w", newline="", encoding="utf-8"
            ) as handle:
                writer = csv.writer(handle)
                writer.writerow(["backend", "insert_seconds", "single_read_ms",
                                 "list_all_seconds", "concurrent_updates_seconds",
                                 "errors", "size_kb"])
                writer.writerows(storage_rows)

    return created


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--credential-file", type=Path,
        help="Existing project credential JSON file for Experiment 1. "
             "If omitted, Experiment 1 is safely skipped.",
    )
    parser.add_argument("--skip-tests", action="store_true",
                        help="Do not run pytest after the experiments.")
    parser.add_argument("--timeout", type=int, default=900,
                        help="Timeout in seconds for each experiment (default: 900).")
    args = parser.parse_args()

    results_dir = ROOT / "results"
    logs_dir = results_dir / "logs"
    raw_dir = results_dir / "raw"
    logs_dir.mkdir(parents=True, exist_ok=True)
    raw_dir.mkdir(parents=True, exist_ok=True)

    run_records: list[dict] = []
    captured_outputs: dict[str, str] = {}

    print("CS2413 results collection")
    print(f"Repository: {ROOT}")
    print(f"Output:     {results_dir}")
    print("-" * 60)

    for module, title in EXPERIMENTS:
        log_path = logs_dir / f"{module}.log"

        if module == "exp01_data_inspection":
            if args.credential_file is None:
                record = {
                    "status": "SKIPPED",
                    "return_code": None,
                    "elapsed_seconds": 0,
                    "command": [],
                    "log": "",
                    "error": "Pass --credential-file with an existing real credential JSON file.",
                    "output": "",
                }
            else:
                credential_file = args.credential_file
                if not credential_file.is_absolute():
                    credential_file = ROOT / credential_file
                if not credential_file.is_file():
                    record = {
                        "status": "SKIPPED",
                        "return_code": None,
                        "elapsed_seconds": 0,
                        "command": [],
                        "log": "",
                        "error": f"Credential file does not exist: {credential_file}",
                        "output": "",
                    }
                else:
                    record = run_command(
                        [sys.executable, "-m", "experiments.exp01_data_inspection",
                         "--json-file", str(credential_file)],
                        log_path, args.timeout,
                    )
        else:
            record = run_command(
                [sys.executable, "-m", f"experiments.{module}"],
                log_path, args.timeout,
            )

        record["experiment"] = module
        record["title"] = title
        run_records.append(record)
        captured_outputs[module] = record.get("output", "")
        print(f"{title}: {record['status']} "
              f"({record['elapsed_seconds']} s)")
        if record["status"] in ("FAIL", "ERROR", "TIMEOUT"):
            print(f"  See {record.get('log') or 'run metadata'}")

    test_record = None
    if not args.skip_tests:
        test_log = logs_dir / "pytest.log"
        if (ROOT / "tests").exists():
            test_record = run_command(
                [sys.executable, "-m", "pytest", "-q"], test_log, args.timeout,
            )
        else:
            test_record = {
                "status": "SKIPPED", "return_code": None,
                "elapsed_seconds": 0, "command": [], "log": "",
                "error": "No tests/ directory found at repository root.",
            }
        test_record["title"] = "Automated pytest suite"
        print(f"Automated pytest suite: {test_record['status']} "
              f"({test_record['elapsed_seconds']} s)")

    charts = make_charts(results_dir, captured_outputs)

    # Keep full stdout out of the JSON metadata; it is already preserved in logs.
    clean_records = []
    for item in run_records:
        clean_records.append({k: v for k, v in item.items() if k != "output"})
    metadata = {
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "repository": str(ROOT),
        "experiments": clean_records,
        "automated_tests": test_record,
        "charts": charts,
    }
    (raw_dir / "run_metadata.json").write_text(
        json.dumps(metadata, indent=2), encoding="utf-8"
    )

    with (raw_dir / "experiment_status.csv").open(
        "w", newline="", encoding="utf-8"
    ) as handle:
        writer = csv.writer(handle)
        writer.writerow(["experiment", "title", "status", "elapsed_seconds",
                         "return_code", "log", "notes"])
        for item in run_records:
            writer.writerow([
                item["experiment"], item["title"], item["status"],
                item["elapsed_seconds"], item["return_code"],
                item["log"], item["error"],
            ])

    lines = [
        "# CS2413 Project - Experiment and Test Results",
        "",
        f"Generated (UTC): {metadata['generated_at_utc']}",
        "",
        "## Experiment execution summary",
        "",
        "| Experiment | Result | Runtime (s) | Log |",
        "|---|---:|---:|---|",
    ]
    for item in run_records:
        log = f"`{item['log']}`" if item["log"] else "—"
        lines.append(
            f"| {item['title']} | **{item['status']}** | "
            f"{item['elapsed_seconds']} | {log} |"
        )
    if test_record is not None:
        log = f"`{test_record['log']}`" if test_record.get("log") else "—"
        lines.extend([
            "",
            "## Automated tests",
            "",
            f"- **Result:** {test_record['status']}",
            f"- **Runtime:** {test_record['elapsed_seconds']} seconds",
            f"- **Log:** {log}",
        ])
        if test_record.get("error"):
            lines.append(f"- **Note:** {test_record['error']}")

    lines.extend([
        "",
        "## Generated graphs",
        "",
    ])
    if charts:
        lines.extend([f"- `{chart}`" for chart in charts])
    else:
        lines.append("No graphs were generated. Check experiment logs and matplotlib installation.")
    lines.extend([
        "",
        "## Interpretation and reporting notes",
        "",
        "- A **PASS** means the experiment process returned exit code 0; consult its log for the individual checks and measured values.",
        "- A **FAIL**, **ERROR**, or **TIMEOUT** must be investigated before reporting the experiment as successful.",
        "- Experiment 1 is skipped unless an existing credential JSON file is supplied with `--credential-file`. This prevents the experiment's fallback mock database from being used as project evidence.",
        "- The hashing experiment's dictionary-attack results use its own fixed test set and time limit. They should not be generalized to all passwords or attackers.",
        "- The online attack experiment is a controlled local simulation using three incorrect guesses followed by the correct password, not a real-world attack benchmark.",
        "- MFA, session, integrity, and other functional checks are retained in their individual logs; present these primarily as test-result tables rather than inventing numerical graphs.",
        "- Graphs are generated only from values printed by the experiment scripts. If a parser cannot find a table or measurement, it does not fabricate replacement data.",
        "- Include the relevant graphs and interpretation in the final report, and retain the `results/logs/` and `results/raw/` files as supporting evidence.",
        "",
        "## Re-running",
        "",
        "Run `python generate_results.py` from the repository root. To include Experiment 1, provide an existing credential JSON file: `python generate_results.py --credential-file data/users.json`.",
        "",
    ])
    (results_dir / "experiment_summary.md").write_text(
        "\n".join(lines), encoding="utf-8"
    )

    print("-" * 60)
    print(f"Finished. Summary: {results_dir / 'experiment_summary.md'}")
    print(f"Logs:    {logs_dir}")
    print(f"Raw:     {raw_dir}")
    print(f"Graphs:  {results_dir / 'graphs'}")
    failures = sum(item["status"] in ("FAIL", "ERROR", "TIMEOUT")
                   for item in run_records)
    if test_record and test_record["status"] in ("FAIL", "ERROR", "TIMEOUT"):
        failures += 1
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
