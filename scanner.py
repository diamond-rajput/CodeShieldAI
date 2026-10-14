
import ast
import re
from pathlib import Path


def scan_code(source_code: str) -> list[dict]:
    """Find potentially insecure patterns in Python source code."""
    findings = []

    def add_finding(line, rule, severity, message, recommendation):
        findings.append({
            "line": line,
            "rule": rule,
            "severity": severity,
            "message": message,
            "recommendation": recommendation,
        })

    # Parse the source to detect syntax errors.
    try:
        tree = ast.parse(source_code)
    except SyntaxError as error:
        return [{
            "line": error.lineno or 1,
            "rule": "SYNTAX-001",
            "severity": "Info",
            "message": f"Python syntax error: {error.msg}",
            "recommendation": "Fix the syntax error before scanning further.",
        }]

    lines = source_code.splitlines()

    # Rule 1: Potentially unsafe dynamic execution.
    for node in ast.walk(tree):
        if isinstance(node, (ast.Call,)):
            function = node.func
            if isinstance(function, ast.Name) and function.id in {
                "eval", "exec"
            }:
                add_finding(
                    node.lineno,
                    "PY-EXEC-001",
                    "High",
                    f"Use of {function.id}() can execute dynamic code.",
                    "Avoid dynamic execution or strictly validate the input.",
                )

    # Rule 2: SQL queries built using f-strings.
    for node in ast.walk(tree):
        if isinstance(node, ast.JoinedStr):
            parent_context = ast.get_source_segment(source_code, node) or ""
            if re.search(r"\b(SELECT|INSERT|UPDATE|DELETE)\b", parent_context, re.I):
                add_finding(
                    node.lineno,
                    "SQL-001",
                    "High",
                    "SQL-like query uses string interpolation.",
                    "Use parameterized queries instead of interpolating values.",
                )

    # Rule 3: Possible hardcoded credentials.
    secret_pattern = re.compile(
        r"""(?i)\b(password|passwd|api_key|secret|token)\b\s*=\s*["'][^"']+["']"""
    )
    for line_number, line in enumerate(lines, start=1):
        if secret_pattern.search(line):
            add_finding(
                line_number,
                "SECRET-001",
                "High",
                "Possible hardcoded secret or credential.",
                "Load secrets from environment variables or a secret manager.",
            )

    # Rule 4: Potentially unsafe shell execution.
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            function = node.func
            if (
                isinstance(function, ast.Attribute)
                and function.attr in {"system", "popen"}
            ):
                add_finding(
                    node.lineno,
                    "CMD-001",
                    "Medium",
                    "Potentially unsafe shell or process execution.",
                    "Prefer subprocess with an argument list and shell=False.",
                )

    # Remove duplicate findings.
    unique_findings = []
    seen = set()
    for finding in findings:
        key = (finding["line"], finding["rule"])
        if key not in seen:
            seen.add(key)
            unique_findings.append(finding)

    return sorted(unique_findings, key=lambda item: item["line"])


def scan_file(file_path: str) -> list[dict]:
    """Scan a Python source file."""
    path = Path(file_path)
    if path.suffix.lower() != ".py":
        raise ValueError("Please select a Python (.py) file.")

    source = path.read_text(encoding="utf-8")
    return scan_code(source)


if __name__ == "__main__":
    sample = '''
import os

password = "demo-password"
query = f"SELECT * FROM users WHERE name = {user_name}"
result = eval(user_input)
os.system(command)
'''

    print("CodeShield AI — Sample Scan")
    for item in scan_code(sample):
        print(
            f"[{item['severity']}] Line {item['line']} "
            f"{item['rule']}: {item['message']}"
        )
        print(f"  Recommendation: {item['recommendation']}")
