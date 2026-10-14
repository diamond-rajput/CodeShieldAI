
import json
import sqlite3
from datetime import datetime
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent
DB_PATH = BASE_DIR / "data" / "scan_history.db"


def get_connection():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)

    connection = sqlite3.connect(DB_PATH, timeout=10)
    connection.row_factory = sqlite3.Row
    return connection


def initialize_database():
    with get_connection() as connection:
        connection.execute("""
            CREATE TABLE IF NOT EXISTS scan_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scanned_at TEXT NOT NULL,
                filename TEXT,
                total_findings INTEGER NOT NULL,
                high_count INTEGER NOT NULL,
                medium_count INTEGER NOT NULL,
                low_count INTEGER NOT NULL,
                info_count INTEGER NOT NULL,
                findings_json TEXT NOT NULL
            )
        """)


def save_scan(findings, filename="Pasted source code"):
    findings = [dict(item) for item in findings]

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

    with get_connection() as connection:
        cursor = connection.execute(
            """
            INSERT INTO scan_history (
                scanned_at,
                filename,
                total_findings,
                high_count,
                medium_count,
                low_count,
                info_count,
                findings_json
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                datetime.now().astimezone().isoformat(timespec="seconds"),
                filename,
                len(findings),
                high,
                medium,
                low,
                info,
                json.dumps(findings, ensure_ascii=False),
            ),
        )

        return cursor.lastrowid


def get_scan_history(limit=100):
    with get_connection() as connection:
        rows = connection.execute(
            """
            SELECT
                id,
                scanned_at,
                filename,
                total_findings,
                high_count,
                medium_count,
                low_count,
                info_count
            FROM scan_history
            ORDER BY id DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()

    return [dict(row) for row in rows]


def get_scan_by_id(scan_id):
    with get_connection() as connection:
        row = connection.execute(
            """
            SELECT *
            FROM scan_history
            WHERE id = ?
            """,
            (scan_id,),
        ).fetchone()

    if row is None:
        return None

    result = dict(row)
    result["findings"] = json.loads(result.pop("findings_json"))
    return result


initialize_database()
