"""Assessment API routes.

Endpoints are plain ``def`` (not ``async def``) on purpose. ``requests`` is
blocking, so FastAPI runs these in its thread pool instead of on the event loop.

Every endpoint that triggers outbound requests is rate limited per client IP
(``ASSESSMENTS_PER_MINUTE``, default 10).
"""

from __future__ import annotations

import json
import logging
from typing import Any
from urllib.parse import urlsplit

from fastapi import APIRouter, Depends, HTTPException, Path, Query, Request, Response
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from database import connection as db
from models.product import ExtractionResult
from models.report import AssessmentReport
from models.source import SourceDiscoveryResult
from services import jobs
from services.assessment_engine import run_assessment
from services.platform_detector import PlatformDetectionResult, detect_platform
from services.product_extractor import extract_products
from services.rate_limit import assessment_limiter
from services.source_detector import discover_sources
from services.url_validator import (
    CLIENT_ERROR_CODES,
    MAX_URL_LENGTH,
    ErrorCode,
    TargetError,
    ValidationResult,
    normalize_url,
    resolve_public_ips,
    validate_target,
)

logger = logging.getLogger("assessment.routes")
router = APIRouter(prefix="/api/assessment", tags=["assessment"])


def rate_limited(request: Request) -> None:
    client = request.client.host if request.client else "unknown"
    if not assessment_limiter.allow(client):
        raise HTTPException(status_code=429, detail="Too many assessments; try again in a minute.",
                            headers={"Retry-After": "60"})


class URLRequest(BaseModel):
    url: str = Field(..., min_length=1, max_length=MAX_URL_LENGTH, examples=["https://example-store.com"])


class PlatformDetectionResponse(BaseModel):
    validation: ValidationResult
    platform: PlatformDetectionResult | None  # None if the URL was rejected before fetching


class SourceDiscoveryResponse(PlatformDetectionResponse):
    discovery: SourceDiscoveryResult


class ProductExtractionResponse(SourceDiscoveryResponse):
    extraction: ExtractionResult


class StartResponse(BaseModel):
    id: int
    status: str
    normalized_url: str


class ErrorResponse(BaseModel):
    error_code: str
    error: str


class HistoryItem(BaseModel):
    id: int
    url: str
    normalized_url: str | None
    domain: str | None
    platform: str | None
    status: str
    compatibility_status: str | None
    current_step: str | None
    error_message: str | None
    created_at: str
    updated_at: str
    completed_at: str | None


class HistoryPage(BaseModel):
    items: list[HistoryItem]
    page: int
    page_size: int
    total: int
    summary: dict[str, int]


class AssessmentRecordResponse(HistoryItem):
    report_schema_version: str | None = None
    report: dict[str, Any] | None = None


def _domain(url: str | None) -> str | None:
    return (urlsplit(url).hostname if url else None) or None


# ----------------------------------------------------------------- individual stages
@router.post("/validate", response_model=ValidationResult, dependencies=[Depends(rate_limited)],
             responses={400: {"model": ValidationResult, "description": "Invalid or unsafe URL"}})
def validate(req: URLRequest, response: Response) -> ValidationResult:
    """Validate the URL, apply the SSRF policy, and check the site is reachable.
    400 for invalid/unsafe URLs; 200 otherwise (see ``is_accessible`` / ``error_code``)."""
    fetch = validate_target(req.url)
    if fetch.result.error_code in CLIENT_ERROR_CODES:
        response.status_code = 400
    return fetch.result


@router.post("/detect-platform", response_model=PlatformDetectionResponse, dependencies=[Depends(rate_limited)],
             responses={400: {"model": PlatformDetectionResponse, "description": "Invalid or unsafe URL"}})
def detect(req: URLRequest, response: Response) -> PlatformDetectionResponse:
    """Fetch the page safely, then identify the platform from that single response."""
    fetch = validate_target(req.url)
    if fetch.result.error_code in CLIENT_ERROR_CODES:
        response.status_code = 400
        return PlatformDetectionResponse(validation=fetch.result, platform=None)
    platform = detect_platform(html=fetch.html, headers=fetch.headers, cookie_names=fetch.cookie_names,
                               final_url=fetch.result.final_url,
                               blocked=fetch.result.error_code == ErrorCode.BOT_PROTECTION)
    return PlatformDetectionResponse(validation=fetch.result, platform=platform)


@router.post("/detect-sources", response_model=SourceDiscoveryResponse, dependencies=[Depends(rate_limited)],
             responses={400: {"model": SourceDiscoveryResponse, "description": "Invalid or unsafe URL"}})
def detect_sources(req: URLRequest, response: Response) -> SourceDiscoveryResponse:
    """Probe platform APIs, JSON-LD, robots.txt/sitemaps and product feeds."""
    home, platform, discovery, _ = discover_sources(req.url)
    if home.result.error_code in CLIENT_ERROR_CODES:
        response.status_code = 400
    return SourceDiscoveryResponse(validation=home.result, platform=platform, discovery=discovery)


@router.post("/extract-products", response_model=ProductExtractionResponse, dependencies=[Depends(rate_limited)],
             responses={400: {"model": ProductExtractionResponse, "description": "Invalid or unsafe URL"}})
def extract(req: URLRequest, response: Response) -> ProductExtractionResponse:
    """Discover sources, then extract up to 5 normalized products."""
    home, platform, discovery, extraction = extract_products(req.url)
    if home.result.error_code in CLIENT_ERROR_CODES:
        response.status_code = 400
    return ProductExtractionResponse(validation=home.result, platform=platform,
                                     discovery=discovery, extraction=extraction)


# ----------------------------------------------------------------- full assessment
@router.post("/analyse", response_model=AssessmentReport, dependencies=[Depends(rate_limited)],
             responses={400: {"model": AssessmentReport, "description": "Invalid or unsafe URL"}})
def analyse(req: URLRequest, response: Response) -> AssessmentReport:
    """Run the full assessment synchronously, save it, and return the unified report.
    The saved row id is returned in the ``X-Assessment-Id`` header."""
    report = run_assessment(req.url)
    if report.target.error_code in CLIENT_ERROR_CODES:
        response.status_code = 400       # rejected URLs are not stored in history
        return report
    try:
        response.headers["X-Assessment-Id"] = str(jobs.persist_report(report))
    except Exception:  # storage failure must not lose the report the caller is waiting for
        logger.exception("Could not persist assessment report")
    return report


@router.post("/start", response_model=StartResponse, status_code=202, dependencies=[Depends(rate_limited)],
             responses={400: {"model": ErrorResponse}, 429: {"description": "Rate limited or queue full"}})
def start(req: URLRequest):
    """Validate the URL now (fast, so the UI can show an error immediately), then run
    the assessment in the background. Poll ``GET /api/assessment/{id}`` for progress."""
    try:
        normalized = normalize_url(req.url)
        resolve_public_ips(urlsplit(normalized).hostname or "")
    except TargetError as exc:
        return JSONResponse(status_code=400, content={"error_code": exc.code.value, "error": exc.message})
    try:
        assessment_id = jobs.submit(req.url, normalized)
    except jobs.QueueFullError:
        raise HTTPException(status_code=429, detail="Assessment queue is full; try again shortly.",
                            headers={"Retry-After": "30"})
    return StartResponse(id=assessment_id, status="pending", normalized_url=normalized)


# ----------------------------------------------------------------- history
@router.get("/history", response_model=HistoryPage)
def history(page: int = Query(1, ge=1, le=100_000),
            page_size: int = Query(20, ge=1, le=db.MAX_PAGE_SIZE)) -> HistoryPage:
    """Saved assessments, newest first (no report bodies; fetch one by id for that)."""
    rows, total, summary = db.list_assessments(page, page_size)
    items = [HistoryItem(**row, domain=_domain(row["normalized_url"] or row["url"])) for row in rows]
    return HistoryPage(items=items, page=page, page_size=page_size, total=total, summary=summary)


@router.get("/{assessment_id}", response_model=AssessmentRecordResponse,
            responses={404: {"description": "Not found"}})
def get_one(assessment_id: int = Path(..., ge=1, le=2**63 - 1)) -> AssessmentRecordResponse:
    """One assessment: status/progress while running, and the full report when finished."""
    row = db.get_assessment(assessment_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Assessment not found.")
    report = None
    if row.get("report_json"):
        try:
            report = json.loads(row["report_json"])
        except json.JSONDecodeError:
            logger.error("Stored report for assessment %s is not valid JSON", assessment_id)
            row["error_message"] = row.get("error_message") or "Stored report is corrupt."
    fields = {k: v for k, v in row.items() if k in AssessmentRecordResponse.model_fields}
    return AssessmentRecordResponse(**fields, domain=_domain(row["normalized_url"] or row["url"]), report=report)
