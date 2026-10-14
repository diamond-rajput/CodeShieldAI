
import json
import subprocess
import sys
import tempfile
from pathlib import Path


def scan_with_bandit(source_code: str) -> dict:
    """Run Bandit against Python source code in a temporary file."""

    temp_path = None

    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            suffix=".py",
            encoding="utf-8",
            delete=False,
        ) as temp_file:
            temp_file.write(source_code)
            temp_path = Path(temp_file.name)

        command = [
            sys.executable,
            "-m",
            "bandit",
            "-f",
            "json",
            str(temp_path),
        ]

        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )

        # Bandit can return a nonzero status when findings exist.
        if result.returncode not in (0, 1):
            return {
                "success": False,
                "findings": [],
                "error": result.stderr.strip()
                or "Bandit could not complete the scan.",
            }

        try:
            report = json.loads(result.stdout)
        except json.JSONDecodeError:
            return {
                "success": False,
                "findings": [],
                "error": result.stderr.strip()
                or "Could not read Bandit's JSON report.",
            }

        findings = []

        for issue in report.get("results", []):
            findings.append({
                "line": issue.get("line_number", 1),
                "rule": issue.get("test_id", "UNKNOWN"),
                "severity": issue.get("issue_severity", "LOW").title(),
                "confidence": issue.get(
                    "issue_confidence", "LOW"
                ).title(),
                "message": issue.get("issue_text", ""),
                "recommendation": (
                    issue.get("more_info", "")
                    or "Review the code and apply a secure alternative."
                ),
                "source": "Bandit",
            })

        return {
            "success": True,
            "findings": findings,
            "error": "",
        }

    except subprocess.TimeoutExpired:
        return {
            "success": False,
            "findings": [],
            "error": "Bandit scan timed out after 30 seconds.",
        }
    except OSError as error:
        return {
            "success": False,
            "findings": [],
            "error": str(error),
        }
    finally:
        if temp_path is not None:
            temp_path.unlink(missing_ok=True)


if __name__ == "__main__":
    sample = '''
import subprocess

user_input = input("Enter a command: ")
subprocess.run(user_input, shell=True)
'''

    report = scan_with_bandit(sample)

    if not report["success"]:
        print("Scan failed:", report["error"])
    else:
        print("CodeShield AI — Bandit Scan")
        print("Findings:", len(report["findings"]))

        for issue in report["findings"]:
            print(
                f"[{issue['severity']}] "
                f"{issue['rule']} | Line {issue['line']}: "
                f"{issue['message']}"
            )
