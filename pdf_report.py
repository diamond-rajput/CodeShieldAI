
from datetime import datetime
from io import BytesIO
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
    KeepTogether,
)


def generate_pdf_report(findings, source_code=""):
    """
    Generate a PDF security report from CodeShield AI findings.
    Returns the PDF as bytes for Streamlit's download button.
    """

    buffer = BytesIO()

    document = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        rightMargin=16 * mm,
        leftMargin=16 * mm,
        topMargin=18 * mm,
        bottomMargin=18 * mm,
        title="CodeShield AI Security Report",
        author="CodeShield AI",
    )

    styles = getSampleStyleSheet()

    styles.add(
        ParagraphStyle(
            name="ReportTitle",
            parent=styles["Title"],
            alignment=TA_CENTER,
            textColor=colors.HexColor("#17365D"),
            spaceAfter=8,
        )
    )

    styles.add(
        ParagraphStyle(
            name="SmallText",
            parent=styles["BodyText"],
            fontSize=8,
            leading=10,
            textColor=colors.HexColor("#555555"),
        )
    )

    styles.add(
        ParagraphStyle(
            name="FindingHeading",
            parent=styles["Heading3"],
            textColor=colors.HexColor("#17365D"),
            spaceBefore=8,
            spaceAfter=4,
        )
    )

    story = []

    story.append(
        Paragraph("CodeShield AI", styles["ReportTitle"])
    )

    story.append(
        Paragraph(
            "Source Code Security Analysis Report",
            styles["Heading2"],
        )
    )

    story.append(Spacer(1, 5 * mm))

    story.append(
        Paragraph(
            f"<b>Generated:</b> "
            f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            styles["BodyText"],
        )
    )

    story.append(Spacer(1, 4 * mm))

    # Count findings by severity
    high = sum(
        str(item.get("severity", "")).lower() == "high"
        for item in findings
    )

    medium = sum(
        str(item.get("severity", "")).lower() == "medium"
        for item in findings
    )

    low = sum(
        str(item.get("severity", "")).lower() == "low"
        for item in findings
    )

    info = sum(
        str(item.get("severity", "")).lower()
        in {"info", "informational", "undefined"}
        for item in findings
    )

    other = len(findings) - high - medium - low - info

    summary_data = [
        ["Metric", "Count"],
        ["Total findings", str(len(findings))],
        ["High severity", str(high)],
        ["Medium severity", str(medium)],
        ["Low severity", str(low)],
        ["Informational", str(info)],
        ["Other", str(other)],
    ]

    summary_table = Table(
        summary_data,
        colWidths=[85 * mm, 45 * mm],
        repeatRows=1,
    )

    summary_table.setStyle(
        TableStyle([
            (
                "BACKGROUND",
                (0, 0),
                (-1, 0),
                colors.HexColor("#17365D"),
            ),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.lightgrey),
            ("BACKGROUND", (0, 1), (-1, -1), colors.whitesmoke),
            ("PADDING", (0, 0), (-1, -1), 7),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ])
    )

    story.append(
        Paragraph("Executive Summary", styles["Heading2"])
    )
    story.append(summary_table)
    story.append(Spacer(1, 6 * mm))

    story.append(
        Paragraph("Detailed Findings", styles["Heading2"])
    )

    if not findings:
        story.append(
            Paragraph(
                "No configured scanner rules reported findings. "
                "This does not guarantee that the source code is secure.",
                styles["BodyText"],
            )
        )

    for index, item in enumerate(findings, start=1):
        severity = escape(str(item.get("severity", "Unknown")))
        rule = escape(str(item.get("rule", "UNKNOWN")))
        scanner = escape(str(item.get("source", "Unknown")))
        line = escape(str(item.get("line", "?")))

        message = escape(
            str(item.get("message", "No description available."))
        )
        recommendation = escape(
            str(
                item.get(
                    "recommendation",
                    "Review the code manually.",
                )
            )
        )

        heading = (
            f"{index}. [{severity}] {rule} "
            f"(Line {line})"
        )

        section = [
            Paragraph(heading, styles["FindingHeading"]),
            Paragraph(
                f"<b>Scanner:</b> {scanner}",
                styles["BodyText"],
            ),
            Spacer(1, 2 * mm),
            Paragraph(
                f"<b>Finding:</b> {message}",
                styles["BodyText"],
            ),
            Spacer(1, 2 * mm),
            Paragraph(
                f"<b>Recommendation:</b> {recommendation}",
                styles["BodyText"],
            ),
            Spacer(1, 3 * mm),
        ]

        if item.get("confidence"):
            confidence = escape(str(item["confidence"]))
            section.append(
                Paragraph(
                    f"<b>Confidence:</b> {confidence}",
                    styles["SmallText"],
                )
            )
            section.append(Spacer(1, 2 * mm))

        # Include the relevant source line when available.
        line_number = item.get("line")
        code_lines = source_code.splitlines()

        if (
            isinstance(line_number, int)
            and 1 <= line_number <= len(code_lines)
        ):
            code_line = escape(code_lines[line_number - 1])

            section.append(
                Paragraph(
                    f"<b>Source line {line_number}:</b> "
                    f"<font name='Courier'>{code_line}</font>",
                    styles["SmallText"],
                )
            )

        story.append(KeepTogether(section))
        story.append(Spacer(1, 3 * mm))

    story.append(Spacer(1, 5 * mm))

    story.append(
        Paragraph(
            "<b>Important limitation:</b> This report summarizes "
            "automated static-analysis findings. Findings may be "
            "false positives, and scanners may miss vulnerabilities. "
            "The experimental ML score is not a calibrated probability "
            "of a real vulnerability. Review the code and findings "
            "manually before making security decisions.",
            styles["SmallText"],
        )
    )

    def add_page_number(canvas, doc):
        canvas.saveState()
        canvas.setFont("Helvetica", 8)
        canvas.setFillColor(colors.grey)
        canvas.drawCentredString(
            A4[0] / 2,
            10 * mm,
            f"CodeShield AI | Page {doc.page}",
        )
        canvas.restoreState()

    document.build(
        story,
        onFirstPage=add_page_number,
        onLaterPages=add_page_number,
    )

    pdf_bytes = buffer.getvalue()
    buffer.close()

    return pdf_bytes
