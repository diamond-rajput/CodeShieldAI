
from pathlib import Path

import pandas as pd
import plotly.express as px
import streamlit as st

from scanner import scan_code
from bandit_scanner import scan_with_bandit
from ml_scanner import predict_code_risk
from pdf_report import generate_pdf_report
from history_db import (
    get_scan_history,
    get_scan_by_id,
    save_scan,
)

st.set_page_config(
    page_title="CodeShield AI",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)


# --------------------------------------------------
# Styling
# --------------------------------------------------

def load_css():
    css_path = Path(__file__).parent / "assets" / "style.css"

    if css_path.exists():
        css = css_path.read_text(encoding="utf-8")
        st.markdown(f"<style>{css}</style>", unsafe_allow_html=True)


load_css()


# --------------------------------------------------
# Helpers
# --------------------------------------------------

def normalize_findings(findings, source):
    """Normalize findings from different scanners into one format."""
    normalized = []

    if not isinstance(findings, list):
        return normalized

    for item in findings:
        if not isinstance(item, dict):
            continue

        finding = dict(item)
        finding.setdefault("line", 0)
        finding.setdefault("rule", "UNKNOWN")
        finding.setdefault("severity", "Info")
        finding.setdefault("message", "No description provided.")
        finding.setdefault("recommendation", "Review this finding manually.")
        finding.setdefault("source", source)

        normalized.append(finding)

    return normalized


def get_severity(finding):
    return str(finding.get("severity", "Info")).strip().lower()


def severity_counts(findings):
    return {
        "High": sum(get_severity(f) == "high" for f in findings),
        "Medium": sum(get_severity(f) == "medium" for f in findings),
        "Low": sum(get_severity(f) == "low" for f in findings),
        "Info / Other": sum(
            get_severity(f) not in {"high", "medium", "low"}
            for f in findings
        ),
    }


def display_findings(findings):
    if not findings:
        st.success("No findings were reported by the selected scanners.")
        st.caption(
            "This does not prove the code is secure. Scanner coverage is limited."
        )
        return

    df = pd.DataFrame(findings)

    preferred_columns = [
        "severity",
        "rule",
        "line",
        "source",
        "message",
        "recommendation",
    ]
    columns = [c for c in preferred_columns if c in df.columns]

    st.dataframe(
        df[columns],
        use_container_width=True,
        hide_index=True,
    )

    st.subheader("Finding details")

    for index, finding in enumerate(findings, start=1):
        severity = finding.get("severity", "Info")
        rule = finding.get("rule", "UNKNOWN")
        line = finding.get("line", 0)
        source = finding.get("source", "Scanner")
        message = finding.get("message", "No description provided.")

        with st.expander(
            f"{severity} · {rule} · Line {line} · {source}"
        ):
            st.write(message)
            st.markdown("**Recommendation**")
            st.write(
                finding.get(
                    "recommendation",
                    "Review this finding manually.",
                )
            )

            if finding.get("confidence") is not None:
                st.write(
                    f"Confidence reported by scanner: "
                    f"{finding['confidence']}"
                )


def export_findings(findings):
    df = pd.DataFrame(findings)
    return df.to_csv(index=False).encode("utf-8")


def run_selected_scanners(source_code, selected_scanners):
    findings = []
    errors = []

    total_steps = len(selected_scanners)
    progress = st.progress(0, text="Preparing scan...")

    for step, scanner_name in enumerate(selected_scanners, start=1):
        progress.progress(
            (step - 1) / total_steps,
            text=f"Running {scanner_name}...",
        )

        try:
            if scanner_name == "Custom Heuristic Scanner":
                results = scan_code(source_code)
                findings.extend(
                    normalize_findings(results, "Custom")
                )

            elif scanner_name == "Bandit":
                result = scan_with_bandit(source_code)

                if isinstance(result, dict):
                    results = result.get("findings", [])
                    error_message = result.get("error")
                    if error_message:
                        errors.append(f"Bandit: {error_message}")
                else:
                    results = result

                findings.extend(
                    normalize_findings(results, "Bandit")
                )

            elif scanner_name == "Experimental ML Classifier":
                result = predict_code_risk(source_code)

                if isinstance(result, dict):
                    prediction = result.get(
                        "prediction",
                        "Unknown prediction",
                    )
                    score = result.get("risk_score")
                    warning = result.get("warning")

                    findings.append({
                        "line": 0,
                        "rule": "ML-PREDICTION",
                        "severity": "Info",
                        "message": str(prediction),
                        "recommendation": (
                            "Treat this experimental prediction as a "
                            "triage hint. Review the source code manually "
                            "and use dedicated security testing."
                        ),
                        "source": "ML",
                        "risk_score": score,
                        "warning": warning,
                    })

                else:
                    findings.append({
                        "line": 0,
                        "rule": "ML-PREDICTION",
                        "severity": "Info",
                        "message": str(result),
                        "recommendation": (
                            "Treat this experimental prediction as a hint, "
                            "not proof of a vulnerability."
                        ),
                        "source": "ML",
                    })

        except Exception as exc:
            errors.append(f"{scanner_name}: {exc}")

        progress.progress(
            step / total_steps,
            text=f"Finished {scanner_name}",
        )

    progress.empty()
    return findings, errors


# --------------------------------------------------
# Session state
# --------------------------------------------------

if "scan_findings" not in st.session_state:
    st.session_state.scan_findings = []

if "scan_source" not in st.session_state:
    st.session_state.scan_source = ""

if "scan_errors" not in st.session_state:
    st.session_state.scan_errors = []

if "scan_filename" not in st.session_state:
    st.session_state.scan_filename = "Pasted source code"

if "scan_completed" not in st.session_state:
    st.session_state.scan_completed = False

if "current_scan_id" not in st.session_state:
    st.session_state.current_scan_id = None


# --------------------------------------------------
# Sidebar navigation
# --------------------------------------------------

with st.sidebar:
    st.title("🛡️ CodeShield AI")
    st.caption("Intelligent Source Code Vulnerability Analyzer")

    page = st.radio(
        "Navigation",
        [
            "Dashboard",
            "Security Findings",
            "Scan History",
            "About",
        ],
        key="navigation_page",
    )

    st.divider()

    st.markdown("**Scanning engines**")
    st.caption("✓ Custom heuristic scanner")
    st.caption("✓ Bandit static analysis")
    st.caption("✓ Experimental ML classifier")

    st.divider()
    st.caption("Security analysis assistance — not a guarantee of safety.")


# --------------------------------------------------
# Header
# --------------------------------------------------

st.title("Security Operations Dashboard")
st.caption(
    "Analyze Python source code, review potential security findings, "
    "and revisit previous scan results."
)


# --------------------------------------------------
# About page
# --------------------------------------------------

if page == "About":
    st.header("About CodeShield AI")

    st.markdown("""
    CodeShield AI combines three analysis approaches:

    - **Custom Heuristic Scanner:** identifies selected suspicious code
      patterns using custom rules.
    - **Bandit:** runs a static-analysis tool for Python security issues.
    - **Experimental ML Classifier:** provides an experimental
      text-classification signal learned from a small illustrative dataset.

    ### Persistent scan history

    Completed scans are saved to a local SQLite database. History includes
    the scan timestamp, filename, severity counts, and saved findings.
    The original source code is not stored in the history database.

    ### Important limitations

    - Findings may include false positives or missed vulnerabilities.
    - An empty report does not mean that code is secure.
    - ML scores are not calibrated probabilities of real vulnerabilities.
    - Review findings and test code in an appropriate development environment.
    """)


# --------------------------------------------------
# Scan History page
# --------------------------------------------------

elif page == "Scan History":
    st.header("Persistent Scan History")
    st.write(
        "Browse saved scan results. History remains available after "
        "the dashboard is restarted, provided the database file is kept."
    )

    history = get_scan_history(limit=200)

    if not history:
        st.info(
            "No saved scans yet. Run a scan from the Dashboard first."
        )
    else:
        history_df = pd.DataFrame(history)

        history_df = history_df.rename(columns={
            "id": "Scan ID",
            "scanned_at": "Date and time",
            "filename": "Filename",
            "total_findings": "Total findings",
            "high_count": "High",
            "medium_count": "Medium",
            "low_count": "Low",
            "info_count": "Info",
        })

        st.dataframe(
            history_df,
            use_container_width=True,
            hide_index=True,
        )

        scan_ids = [item["id"] for item in history]

        selected_id = st.selectbox(
            "Choose a scan to inspect",
            options=scan_ids,
            format_func=lambda scan_id: (
                f"Scan #{scan_id} — "
                f"{next(
                    (item['scanned_at'] for item in history
                     if item['id'] == scan_id),
                    'Unknown date'
                )}"
            ),
        )

        if st.button("Load Selected Scan", type="primary"):
            saved_scan = get_scan_by_id(selected_id)

            if saved_scan is None:
                st.error("That scan could not be found in the database.")
            else:
                st.session_state.scan_findings = saved_scan["findings"]
                st.session_state.scan_source = ""
                st.session_state.scan_errors = []
                st.session_state.scan_filename = (
                    saved_scan.get("filename") or "Saved scan"
                )
                st.session_state.scan_completed = True
                st.session_state.current_scan_id = saved_scan["id"]

                st.success(f"Loaded scan #{saved_scan['id']}.")

        if (
            st.session_state.scan_completed
            and st.session_state.current_scan_id in scan_ids
        ):
            st.divider()
            st.subheader(
                f"Loaded scan #{st.session_state.current_scan_id}"
            )

            loaded_findings = st.session_state.scan_findings
            counts = severity_counts(loaded_findings)

            c1, c2, c3, c4, c5 = st.columns(5)
            c1.metric("Total", len(loaded_findings))
            c2.metric("High", counts["High"])
            c3.metric("Medium", counts["Medium"])
            c4.metric("Low", counts["Low"])
            c5.metric("Info / Other", counts["Info / Other"])

            display_findings(loaded_findings)

            st.download_button(
                "Download Findings CSV",
                data=export_findings(loaded_findings),
                file_name=(
                    f"codeshield_scan_{st.session_state.current_scan_id}.csv"
                ),
                mime="text/csv",
            )

            pdf_bytes = generate_pdf_report(
                loaded_findings,
                source_code="",
            )

            st.download_button(
                "Download PDF Report",
                data=pdf_bytes,
                file_name=(
                    f"codeshield_scan_{st.session_state.current_scan_id}.pdf"
                ),
                mime="application/pdf",
            )


# --------------------------------------------------
# Dashboard and Security Findings
# --------------------------------------------------

elif page in ("Dashboard", "Security Findings"):
    st.header("Source Code Analysis")

    example_code = '''import subprocess

def run_command(user_input):
    command = f"echo {user_input}"
    return subprocess.run(
        command,
        shell=True,
        capture_output=True,
        text=True
    )
'''

    with st.form("scan_form"):
        uploaded_file = st.file_uploader(
            "Upload a Python file",
            type=["py"],
            help="The file is analyzed locally by the configured scanners.",
        )

        source_input = st.text_area(
            "Or paste Python source code",
            value=example_code,
            height=240,
            placeholder="Paste your Python code here...",
        )

        st.markdown("**Select scanning engines**")

        selected_scanners = []

        if st.checkbox(
            "Custom Heuristic Scanner",
            value=True,
            key="use_custom",
        ):
            selected_scanners.append("Custom Heuristic Scanner")

        if st.checkbox(
            "Bandit Static Analysis",
            value=True,
            key="use_bandit",
        ):
            selected_scanners.append("Bandit")

        if st.checkbox(
            "Experimental ML Classifier",
            value=True,
            key="use_ml",
        ):
            selected_scanners.append("Experimental ML Classifier")

        run_scan = st.form_submit_button(
            "Run Security Scan",
            type="primary",
            use_container_width=True,
        )

    if run_scan:
        if uploaded_file is not None:
            try:
                source_code = uploaded_file.getvalue().decode("utf-8")
                filename = Path(uploaded_file.name).name
            except UnicodeDecodeError:
                st.error(
                    "The uploaded file is not valid UTF-8 text. "
                    "Please use a UTF-8 encoded Python file."
                )
                st.stop()
        else:
            source_code = source_input
            filename = "Pasted source code"

        if not source_code.strip():
            st.warning("Please upload or paste some Python source code.")
        elif not selected_scanners:
            st.warning("Select at least one scanning engine.")
        else:
            findings, errors = run_selected_scanners(
                source_code,
                selected_scanners,
            )

            st.session_state.scan_findings = findings
            st.session_state.scan_source = source_code
            st.session_state.scan_errors = errors
            st.session_state.scan_filename = filename
            st.session_state.scan_completed = True

            # Persist the completed scan without saving the source code.
            try:
                scan_id = save_scan(findings, filename)
                st.session_state.current_scan_id = scan_id
                st.success(
                    f"Scan completed and saved to history as scan #{scan_id}."
                )
            except Exception as exc:
                st.session_state.current_scan_id = None
                st.error(
                    "The scan completed, but saving history failed: "
                    f"{exc}"
                )

    # Display most recent or loaded scan
    if st.session_state.scan_completed:
        findings = st.session_state.scan_findings
        errors = st.session_state.scan_errors

        st.divider()
        st.subheader("Scan Results")

        if st.session_state.current_scan_id is not None:
            st.caption(
                f"Saved scan ID: #{st.session_state.current_scan_id}"
            )

        for error in errors:
            st.warning(error)

        counts = severity_counts(findings)

        c1, c2, c3, c4, c5 = st.columns(5)
        c1.metric("Total Findings", len(findings))
        c2.metric("High", counts["High"])
        c3.metric("Medium", counts["Medium"])
        c4.metric("Low", counts["Low"])
        c5.metric("Info / Other", counts["Info / Other"])

        if findings:
            chart_col1, chart_col2 = st.columns(2)

            with chart_col1:
                st.subheader("Severity Distribution")
                severity_df = pd.DataFrame([
                    {"Severity": name, "Count": count}
                    for name, count in counts.items()
                    if count > 0
                ])

                if not severity_df.empty:
                    fig = px.pie(
                        severity_df,
                        names="Severity",
                        values="Count",
                        hole=0.45,
                    )
                    fig.update_layout(
                        paper_bgcolor="rgba(0,0,0,0)",
                        plot_bgcolor="rgba(0,0,0,0)",
                        font_color="#E5EDF8",
                    )
                    st.plotly_chart(fig, use_container_width=True)

            with chart_col2:
                st.subheader("Findings by Scanner")

                scanner_counts = {}
                for finding in findings:
                    name = finding.get("source", "Unknown")
                    scanner_counts[name] = scanner_counts.get(name, 0) + 1

                scanner_df = pd.DataFrame([
                    {"Scanner": name, "Findings": count}
                    for name, count in scanner_counts.items()
                ])

                if not scanner_df.empty:
                    fig = px.bar(
                        scanner_df,
                        x="Scanner",
                        y="Findings",
                        text="Findings",
                    )
                    fig.update_layout(
                        paper_bgcolor="rgba(0,0,0,0)",
                        plot_bgcolor="rgba(0,0,0,0)",
                        font_color="#E5EDF8",
                    )
                    st.plotly_chart(fig, use_container_width=True)

        st.subheader("Findings Explorer")

        severity_options = [
            "All",
            "High",
            "Medium",
            "Low",
            "Info / Other",
        ]

        filter_col, search_col = st.columns([1, 2])

        with filter_col:
            selected_severity = st.selectbox(
                "Filter by severity",
                severity_options,
            )

        with search_col:
            search_text = st.text_input(
                "Search findings",
                placeholder="Search rule, message, scanner, or recommendation",
            )

        filtered_findings = findings

        if selected_severity != "All":
            if selected_severity == "Info / Other":
                filtered_findings = [
                    f for f in filtered_findings
                    if get_severity(f) not in {"high", "medium", "low"}
                ]
            else:
                filtered_findings = [
                    f for f in filtered_findings
                    if get_severity(f) == selected_severity.lower()
                ]

        if search_text.strip():
            query = search_text.strip().lower()

            filtered_findings = [
                f for f in filtered_findings
                if query in " ".join(
                    str(value) for value in f.values()
                ).lower()
            ]

        st.caption(f"Showing {len(filtered_findings)} finding(s)")
        display_findings(filtered_findings)

        st.download_button(
            "Download Findings CSV",
            data=export_findings(findings),
            file_name=(
                f"codeshield_scan_{st.session_state.current_scan_id or 'latest'}.csv"
            ),
            mime="text/csv",
        )

        pdf_bytes = generate_pdf_report(
            findings,
            source_code=st.session_state.scan_source,
        )

        st.download_button(
            "Download PDF Security Report",
            data=pdf_bytes,
            file_name=(
                f"codeshield_scan_{st.session_state.current_scan_id or 'latest'}.pdf"
            ),
            mime="application/pdf",
        )

        st.caption(
            "Security note: findings are indicators for manual review, "
            "not proof that a vulnerability exists. No findings does not "
            "mean that the code is secure."
        )

else:
    st.info("Choose a page from the sidebar.")
