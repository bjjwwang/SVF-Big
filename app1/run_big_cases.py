#!/usr/bin/env python3
import sys
import subprocess
from pathlib import Path
from datetime import datetime


def find_tests(test_cases_dir: Path) -> list[Path]:
    tests = list(test_cases_dir.glob("*.ll")) + list(test_cases_dir.glob("*.bc"))
    return sorted(tests)


def main() -> int:
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

    start_all = datetime.now()
    for idx, test_path in enumerate(tests, start=1):
        name = test_path.stem
        stdout_file = logs_dir / f"{name}.out"
        stderr_file = logs_dir / f"{name}.err"

        cmd = [sys.executable, str(here / "test-ae.py"), str(test_path)]
        result = subprocess.run(cmd, capture_output=True, text=True)

        stdout_file.write_text(result.stdout or "")
        stderr_file.write_text(result.stderr or "")

        status = "Passed" if result.returncode == 0 else "Failed"
        print(f"Test {idx}/{total} {name} ... {status}")

        if result.returncode == 0:
            passed.append(name)
        else:
            failed.append((name, stdout_file, stderr_file))

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

    print(f"Total time: {duration:.2f} sec")
    return 0 if num_failed == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())


