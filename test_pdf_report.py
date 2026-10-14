
from pathlib import Path

from pdf_report import generate_pdf_report

sample_findings = [
    {
        "source": "Custom",
        "line": 1,
        "rule": "PY-EXEC-001",
        "severity": "High",
        "confidence": "Not rated",
        "message": "Dynamic code execution detected.",
        "recommendation": "Avoid eval() on untrusted input.",
    },
    {
        "source": "Bandit",
        "line": 2,
        "rule": "B404",
        "severity": "Low",
        "confidence": "High",
        "message": "Review subprocess module usage.",
        "recommendation": "Review whether subprocess is necessary.",
    },
]

sample_code = "result = eval(user_input)\nimport subprocess"

pdf_bytes = generate_pdf_report(
    sample_findings,
    source_code=sample_code,
)

output_path = Path("reports") / "test_security_report.pdf"
output_path.parent.mkdir(parents=True, exist_ok=True)
output_path.write_bytes(pdf_bytes)

print("PDF generated successfully!")
print("File:", output_path.resolve())
print("Size:", len(pdf_bytes), "bytes")
