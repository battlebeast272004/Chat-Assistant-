"""Database schema + Pydantic models for the `assessments` table.

The table stores the *full* JSON report as a TEXT blob (`report_json`) plus a
few denormalised columns (`platform`, `status`, ...) so the history list can be
queried and filtered without parsing JSON. `report_schema_version` lets future
consumers (the chat widget / orchestrator) know which report contract a row
was written with.
"""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field

REPORT_SCHEMA_VERSION = "1.0"


class AssessmentStatus(str, Enum):
    PENDING = "pending"      # queued, not started
    RUNNING = "running"      # inspection in progress
    COMPLETED = "completed"  # report generated
    FAILED = "failed"        # our error / site unreachable
    BLOCKED = "blocked"      # site reachable but bot-protection prevented inspection


class Platform(str, Enum):
    WOOCOMMERCE = "woocommerce"
    SHOPIFY = "shopify"
    WIX = "wix"
    MAGENTO = "magento"
    BIGCOMMERCE = "bigcommerce"
    CUSTOM = "custom"
    UNKNOWN = "unknown"


_statuses = ", ".join(f"'{s.value}'" for s in AssessmentStatus)
_platforms = ", ".join(f"'{p.value}'" for p in Platform)

SCHEMA_SQL = f"""
CREATE TABLE IF NOT EXISTS assessments (
    id                    INTEGER PRIMARY KEY AUTOINCREMENT,
    url                   TEXT    NOT NULL,              -- exactly as submitted
    normalized_url        TEXT,                          -- after validation (Stage 2)
    platform              TEXT    CHECK (platform IS NULL OR platform IN ({_platforms})),
    status                TEXT    NOT NULL DEFAULT 'pending'
                                  CHECK (status IN ({_statuses})),
    report_json           TEXT,                          -- full JSON report
    report_schema_version TEXT    NOT NULL DEFAULT '{REPORT_SCHEMA_VERSION}',
    error_message         TEXT,
    compatibility_status  TEXT,                          -- e.g. 'Good candidate' (denormalised for listing)
    assessment_uuid       TEXT,                          -- report.assessment_id
    current_step          TEXT,                          -- engine step while running
    created_at            TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    updated_at            TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    completed_at          TEXT
);

CREATE INDEX IF NOT EXISTS idx_assessments_created_at ON assessments (created_at DESC, id DESC);
CREATE INDEX IF NOT EXISTS idx_assessments_status     ON assessments (status);

-- Keep updated_at current on every UPDATE without relying on application code.
CREATE TRIGGER IF NOT EXISTS trg_assessments_updated_at
AFTER UPDATE ON assessments
FOR EACH ROW WHEN NEW.updated_at = OLD.updated_at
BEGIN
    UPDATE assessments
       SET updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
     WHERE id = NEW.id;
END;
"""

#: Columns added after Stage 1. init_db() adds them to existing databases.
MIGRATION_COLUMNS = {
    "compatibility_status": "TEXT",
    "assessment_uuid": "TEXT",
    "current_step": "TEXT",
}


class AssessmentRecord(BaseModel):
    """One row of the `assessments` table as returned by the API."""

    id: int
    url: str
    normalized_url: str | None = None
    platform: Platform | None = None
    status: AssessmentStatus = AssessmentStatus.PENDING
    report: dict[str, Any] | None = Field(default=None, description="Parsed report_json")
    report_schema_version: str = REPORT_SCHEMA_VERSION
    error_message: str | None = None
    created_at: datetime
    updated_at: datetime
    completed_at: datetime | None = None
