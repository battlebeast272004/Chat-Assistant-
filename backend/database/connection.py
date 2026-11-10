"""SQLite connection management.

Design notes:
- One short-lived connection per unit of work (`get_db()` context manager).
  sqlite3 connections are not safe to share across threads, and FastAPI runs
  sync endpoints in a thread pool, so a global connection would break.
- WAL (Write-Ahead Logging) lets readers keep reading while a writer commits,
  which matters once background assessment jobs write while the UI reads
  history. WAL mode is persisted in the database file, but we set it on every
  connection anyway so a freshly created file is always in WAL mode.
- busy_timeout makes a writer wait for a lock instead of failing immediately
  with "database is locked".
"""

from __future__ import annotations

import os
import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

from typing import Any

from .models import MIGRATION_COLUMNS, SCHEMA_SQL, AssessmentStatus

# Project root = two levels up from this file (backend/database/connection.py).
PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_DB_PATH = PROJECT_ROOT / "data" / "assessments.db"

# Allow overriding the location (e.g. tests or deployments) via env var.
DB_PATH = Path(os.environ.get("ASSESSMENT_DB_PATH", DEFAULT_DB_PATH))


def _configure(conn: sqlite3.Connection) -> None:
    conn.row_factory = sqlite3.Row  # rows behave like dicts: row["url"]
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA synchronous=NORMAL;")  # safe with WAL, much faster
    conn.execute("PRAGMA foreign_keys=ON;")
    conn.execute("PRAGMA busy_timeout=5000;")  # milliseconds


def create_connection() -> sqlite3.Connection:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH, timeout=5.0)
    _configure(conn)
    return conn


@contextmanager
def get_db() -> Iterator[sqlite3.Connection]:
    """Yield a connection; commit on success, roll back on error, always close."""
    conn = create_connection()
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def init_db() -> None:
    """Create tables, indexes and triggers if they don't exist, and add any
    columns introduced after the database was first created (idempotent)."""
    with get_db() as conn:
        conn.executescript(SCHEMA_SQL)
        existing = {row["name"] for row in conn.execute("PRAGMA table_info(assessments)")}
        for column, sql_type in MIGRATION_COLUMNS.items():
            if column not in existing:
                # Identifiers can't be bound as parameters; these come from a
                # hard-coded constant, never from user input.
                conn.execute(f"ALTER TABLE assessments ADD COLUMN {column} {sql_type}")


def get_journal_mode() -> str:
    """Used by the health check to confirm WAL is actually active."""
    with get_db() as conn:
        return conn.execute("PRAGMA journal_mode;").fetchone()[0]


# ==========================================================================
# Assessment persistence. EVERY value is bound with "?" placeholders; no SQL
# is ever built from request data.
# ==========================================================================
_NOW = "strftime('%Y-%m-%dT%H:%M:%fZ', 'now')"
_LIST_COLUMNS = ("id, url, normalized_url, platform, status, compatibility_status, current_step, "
                 "error_message, created_at, updated_at, completed_at")
MAX_PAGE_SIZE = 100


def create_assessment(url: str, normalized_url: str | None,
                      status: AssessmentStatus = AssessmentStatus.PENDING) -> int:
    """Insert a new row (a queued job) and return its id."""
    with get_db() as conn:
        cur = conn.execute(
            "INSERT INTO assessments (url, normalized_url, status) VALUES (?, ?, ?)",
            (url, normalized_url, status.value),
        )
        return int(cur.lastrowid)


def update_progress(assessment_id: int, step: str) -> None:
    with get_db() as conn:
        conn.execute(
            "UPDATE assessments SET status = ?, current_step = ? WHERE id = ?",
            (AssessmentStatus.RUNNING.value, step, assessment_id),
        )


def save_report(
    assessment_id: int,
    *,
    status: AssessmentStatus,
    report_json: str,
    platform: str | None,
    compatibility_status: str | None,
    assessment_uuid: str | None,
    normalized_url: str | None,
    report_schema_version: str,
    error_message: str | None = None,
) -> None:
    """Store a finished report on an existing row."""
    with get_db() as conn:
        conn.execute(
            f"""UPDATE assessments
                   SET status = ?, report_json = ?, platform = ?, compatibility_status = ?,
                       assessment_uuid = ?, normalized_url = COALESCE(?, normalized_url),
                       report_schema_version = ?, error_message = ?, current_step = NULL,
                       completed_at = {_NOW}
                 WHERE id = ?""",
            (status.value, report_json, platform, compatibility_status, assessment_uuid,
             normalized_url, report_schema_version, error_message, assessment_id),
        )


def save_completed_assessment(url: str, **fields: Any) -> int:
    """Insert and complete a row in one step (used by the synchronous /analyse endpoint)."""
    assessment_id = create_assessment(url, fields.get("normalized_url"), AssessmentStatus.RUNNING)
    save_report(assessment_id, **fields)
    return assessment_id


def mark_failed(assessment_id: int, message: str) -> None:
    with get_db() as conn:
        conn.execute(
            f"UPDATE assessments SET status = ?, error_message = ?, current_step = NULL, completed_at = {_NOW} "
            "WHERE id = ?",
            (AssessmentStatus.FAILED.value, message, assessment_id),
        )


def fail_interrupted_assessments() -> int:
    """At startup, any 'pending'/'running' row belongs to a previous process that died."""
    with get_db() as conn:
        cur = conn.execute(
            f"UPDATE assessments SET status = ?, error_message = ?, current_step = NULL, completed_at = {_NOW} "
            "WHERE status IN (?, ?)",
            (AssessmentStatus.FAILED.value, "Interrupted by a server restart.",
             AssessmentStatus.PENDING.value, AssessmentStatus.RUNNING.value),
        )
        return cur.rowcount


def list_assessments(page: int = 1, page_size: int = 20) -> tuple[list[dict], int, dict[str, int]]:
    """Return (rows for the page newest first, total row count, counts by compatibility status)."""
    page = max(1, int(page))
    page_size = max(1, min(int(page_size), MAX_PAGE_SIZE))
    with get_db() as conn:
        rows = conn.execute(
            f"SELECT {_LIST_COLUMNS} FROM assessments ORDER BY created_at DESC, id DESC LIMIT ? OFFSET ?",
            (page_size, (page - 1) * page_size),
        ).fetchall()
        total = conn.execute("SELECT COUNT(*) FROM assessments").fetchone()[0]
        summary = {
            (r[0] or "In progress / failed"): r[1]
            for r in conn.execute("SELECT compatibility_status, COUNT(*) FROM assessments GROUP BY compatibility_status")
        }
    return [dict(r) for r in rows], int(total), summary


def get_assessment(assessment_id: int) -> dict | None:
    with get_db() as conn:
        row = conn.execute(
            f"SELECT {_LIST_COLUMNS}, report_json, report_schema_version, assessment_uuid "
            "FROM assessments WHERE id = ?",
            (assessment_id,),
        ).fetchone()
    return dict(row) if row else None
