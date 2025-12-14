#!/usr/bin/env python3
import sys
import subprocess
from pathlib import Path
from datetime import datetime
import argparse
import time
import re
import csv
import shutil
from typing import Optional, Tuple


def find_tests(test_cases_dir: Path) -> list[Path]:
    tests = list(test_cases_dir.glob("*.ll")) + list(test_cases_dir.glob("*.bc"))
    return sorted(tests)


def parse_max_rss_from_time(stderr_text: str) -> Optional[int]:
    """
    Parse '/usr/bin/time -l' output to get max RSS in bytes (as macOS reports).
    The line usually looks like:
        '  12345678  maximum resident set size'
    """
    pattern = re.compile(r"^\s*(\d+)\s+maximum resident set size\b", re.IGNORECASE | re.MULTILINE)
    m = pattern.search(stderr_text)
    if m:
        try:
            return int(m.group(1))
        except Exception:
            return None
    return None


def run_one_with_metrics(cmd: list[str], timeout: Optional[float] = None) -> Tuple[subprocess.CompletedProcess, float, Optional[int], bool]:
    """
    Run a command and collect:
    - wall-clock (seconds)
    - max RSS via '/usr/bin/time -l' if available (macOS), else None
    - timed_out flag (True if we killed due to timeout)
    Returns (completed_process, elapsed_seconds, max_rss_bytes_or_None, timed_out)
    """
    time_path = shutil.which("/usr/bin/time") or shutil.which("time")
    use_time = False
    wrapped_cmd = cmd
    if time_path and Path(time_path).name == "time":
        # Prefer absolute /usr/bin/time when available; otherwise 'time' may be a shell keyword.
        if str(time_path) == "/usr/bin/time":
            use_time = True
    if use_time:
        wrapped_cmd = ["/usr/bin/time", "-l"] + cmd
    start = time.perf_counter()
    try:
        result = subprocess.run(wrapped_cmd, capture_output=True, text=True, timeout=timeout)
        elapsed = time.perf_counter() - start
        max_rss = parse_max_rss_from_time(result.stderr) if use_time else None
        return result, elapsed, max_rss, False
    except subprocess.TimeoutExpired as e:
        elapsed = time.perf_counter() - start
        # Build a CompletedProcess-like object with a conventional timeout code (124)
        cp = subprocess.CompletedProcess(wrapped_cmd, returncode=124, stdout=e.stdout or "", stderr=e.stderr or "")
        return cp, elapsed, None, True


def main() -> int:
    parser = argparse.ArgumentParser(description="Run big test cases with time and memory metrics.")
    parser.add_argument("--timeout", type=float, default=None, help="Per-test timeout in seconds (default: no timeout)")
    args = parser.parse_args()

    here = Path(__file__).resolve().parent
    repo_root = here.parent
    test_cases_dir = repo_root / "test_cases"
    logs_dir = here / "logs_big"
    logs_dir.mkdir(parents=True, exist_ok=True)

    tests = find_tests(test_cases_dir)
    if not tests:
        print(f"No tests found under {test_cases_dir} (expected *.ll or *.bc)")
        return 1

    total = len(tests)
    print(f"Running {total} big tests")

    passed: list[str] = []
    failed: list[tuple[str, Path, Path]] = []  # (name, stdout_path, stderr_path)
    summary_rows = []

    start_all = datetime.now()
    for idx, test_path in enumerate(tests, start=1):
        name = test_path.stem
        stdout_file = logs_dir / f"{name}.out"
        stderr_file = logs_dir / f"{name}.err"

        cmd = [sys.executable, str(here / "test-ae.py"), str(test_path)]
        result, elapsed_s, max_rss_bytes, timed_out = run_one_with_metrics(cmd, timeout=args.timeout)

        stdout_file.write_text(result.stdout or "")
        stderr_file.write_text(result.stderr or "")

        status = "Passed" if result.returncode == 0 else "Failed"
        killed_sig = None
        if result.returncode < 0:
            killed_sig = -result.returncode
        elif result.returncode >= 128 and result.returncode <= 255:
            # Sometimes shells report 128+SIG
            killed_sig = result.returncode - 128

        rss_mib = (max_rss_bytes / (1024 * 1024)) if max_rss_bytes is not None else None
        extra = []
        extra.append(f"time {elapsed_s:.2f}s")
        if rss_mib is not None:
            extra.append(f"RSS {rss_mib:.1f} MiB")
        if killed_sig:
            extra.append(f"killed by SIG{killed_sig}")
        if timed_out:
            extra.append("timeout")
        print(f"Test {idx}/{total} {name} ... {status} | " + ", ".join(extra))

        if result.returncode == 0:
            passed.append(name)
        else:
            failed.append((name, stdout_file, stderr_file))

        summary_rows.append({
            "name": name,
            "returncode": result.returncode,
            "elapsed_s": round(elapsed_s, 6),
            "max_rss_bytes": max_rss_bytes,
            "max_rss_mib": round(rss_mib, 3) if rss_mib is not None else None,
            "killed_signal": killed_sig,
            "timed_out": timed_out,
            "stdout_path": str(stdout_file),
            "stderr_path": str(stderr_file),
        })

    duration = (datetime.now() - start_all).total_seconds()
    num_failed = len(failed)
    num_passed = len(passed)
    pct_pass = int(round((num_passed / total) * 100)) if total else 0

    if num_failed == 0:
        print(f"{pct_pass}% tests passed, {num_failed} tests failed out of {total}")
    else:
        print(f"{pct_pass}% tests passed, {num_failed} tests failed out of {total}")
        print("Failed tests:")
        for name, out_path, err_path in failed:
            print(f"  - {name} (stdout: {out_path}, stderr: {err_path})")

    # Write CSV summary with metrics
    csv_path = logs_dir / "summary.csv"
    with csv_path.open("w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=[
            "name", "returncode", "killed_signal", "elapsed_s",
            "max_rss_bytes", "max_rss_mib", "timed_out", "stdout_path", "stderr_path",
        ])
        writer.writeheader()
        for row in summary_rows:
            writer.writerow(row)
    print(f"Summary CSV: {csv_path}")

    print(f"Total time: {duration:.2f} sec")
    return 0 if num_failed == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())


