import json
import sqlite3
from contextlib import closing
from datetime import UTC, datetime
from pathlib import Path

from analyzer import machine_type

ROOT = Path(__file__).resolve().parent

SCHEMA_PATH = ROOT / "schema.sql"
DB_PATH = ROOT / "instance" / "binaryscope.db"


def init_db():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)

    sql = SCHEMA_PATH.read_text(encoding="utf-8")

    with closing(sqlite3.connect(DB_PATH)) as conn:
        conn.executescript(sql)
        conn.commit()


def save_analysis(report):
    # Save every single analysis
    sql = """
    INSERT INTO analyses
    (filename, file_size, sha256, pe_format, architecture, analyzed_at, report_json)
    VALUES (?, ?, ?, ?, ?, ?, ?)
    """

    values = (
        report["filename"],
        report["file_size"],
        report["sha256"],
        report["headers"]["pe_type"],
        machine_type(report["headers"]["machine"]),
        datetime.now(UTC).isoformat(),
        json.dumps(report, default=json_default),
    )
    with closing(sqlite3.connect(DB_PATH)) as conn:
        cursor = conn.execute(sql, values)
        conn.commit()
        return cursor.lastrowid


def list_analyses():
    # The history page only needs the summary, not the full report
    sql = """
    SELECT id, filename, file_size, pe_format, architecture, analyzed_at
    FROM analyses
    ORDER BY analyzed_at DESC, id DESC
    LIMIT 50
    """
    with closing(sqlite3.connect(DB_PATH)) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute(sql).fetchall()

    return [dict(row) for row in rows]


def get_analysis(analysis_id):
    sql = """
    SELECT report_json FROM analyses WHERE id = ?
    """
    with closing(sqlite3.connect(DB_PATH)) as conn:
        row = conn.execute(sql, (analysis_id,)).fetchone()

    if row is None:
        return None

    return json.loads(row[0])


def json_default(value):
    if isinstance(value, datetime):
        return value.isoformat()

    raise TypeError(f"Unsupported JSON type: {type(value).__name__}")
