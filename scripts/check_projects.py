"""Run each selected project's tests in an isolated Python process."""
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
PROJECTS = (
    "osint-domain-dashboard",
    "phishing-email-detector",
    "network-monitoring-dashboard",
    "password-strength-checker",
    "mini-vulnerability-scanner",
)


def main():
    failed = []
    for project in PROJECTS:
        print(f"\n{project}", flush=True)
        result = subprocess.run(
            [sys.executable, "-m", "unittest", "discover", "-s", "tests", "-v"],
            cwd=ROOT / project,
            check=False,
        )
        if result.returncode:
            failed.append(project)
    print("\n" + ("FAILED: " + ", ".join(failed) if failed else "OK: 5 project test suites passed."))
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
