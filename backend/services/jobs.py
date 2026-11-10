"""Background assessment jobs and report persistence.

Each `assessments` row is also the job record:
  pending -> running (current_step updated per engine step) -> completed | blocked | failed

The worker pool is bounded: MAX_CONCURRENT_JOBS run at once, and no more than
MAX_QUEUED_JOBS can be waiting. Beyond that, submit() raises QueueFullError
(HTTP 429) instead of piling up work.
"""

from __future__ import annotations

import logging
import os
import threading
from concurrent.futures import ThreadPoolExecutor

from database import connection as db
from database.models import AssessmentStatus
from models.report import AssessmentReport, CompatibilityStatus
from services.assessment_engine import run_assessment

logger = logging.getLogger("assessment.jobs")

MAX_CONCURRENT_JOBS = int(os.environ.get("MAX_CONCURRENT_JOBS", "3"))
MAX_QUEUED_JOBS = int(os.environ.get("MAX_QUEUED_JOBS", "20"))

_executor = ThreadPoolExecutor(max_workers=MAX_CONCURRENT_JOBS, thread_name_prefix="assessment")
_lock = threading.Lock()
_outstanding = 0


class QueueFullError(Exception):
    pass


def report_row_fields(report: AssessmentReport) -> dict:
    """Map a report to the denormalised columns used for listing/filtering."""
    compat = report.compatibility
    if compat.status == CompatibilityStatus.INCOMPLETE and compat.rule in ("R1", "R2"):
        status = AssessmentStatus.FAILED          # unreachable target or internal error
    elif compat.status == CompatibilityStatus.INCOMPLETE and compat.rule == "R4":
        status = AssessmentStatus.BLOCKED         # bot protection / time budget
    else:
        status = AssessmentStatus.COMPLETED
    return {
        "status": status,
        "report_json": report.model_dump_json(),
        "platform": report.platform.detected_platform.value if report.platform else None,
        "compatibility_status": compat.status.value,
        "assessment_uuid": report.assessment_id,
        "normalized_url": report.target.normalized_url,
        "report_schema_version": report.report_schema_version,
        "error_message": compat.reasons[0] if status == AssessmentStatus.FAILED and compat.reasons else None,
    }


def _run(assessment_id: int, url: str) -> None:
    global _outstanding
    try:
        report = run_assessment(url, on_step=lambda step: db.update_progress(assessment_id, step))
        db.save_report(assessment_id, **report_row_fields(report))
    except Exception:
        logger.exception("Assessment job %s crashed", assessment_id)
        try:
            db.mark_failed(assessment_id, "Internal error while running the assessment.")
        except Exception:
            logger.exception("Could not mark assessment %s as failed", assessment_id)
    finally:
        with _lock:
            _outstanding -= 1


def submit(url: str, normalized_url: str | None) -> int:
    """Create the row and queue the job. Returns the assessment id."""
    global _outstanding
    with _lock:
        if _outstanding >= MAX_CONCURRENT_JOBS + MAX_QUEUED_JOBS:
            raise QueueFullError()
        _outstanding += 1
    try:
        assessment_id = db.create_assessment(url, normalized_url)
        _executor.submit(_run, assessment_id, url)
        return assessment_id
    except Exception:
        with _lock:
            _outstanding -= 1
        raise


def persist_report(report: AssessmentReport) -> int:
    """Save a report produced synchronously (POST /analyse)."""
    return db.save_completed_assessment(report.input_url, **report_row_fields(report))
