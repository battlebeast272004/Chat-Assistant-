"""Unified assessment report: the JSON contract consumed by the UI and the future orchestrator."""

from __future__ import annotations

from datetime import datetime
from enum import Enum

from pydantic import BaseModel, Field

from models.product import ExtractionResult
from models.source import SourceDiscoveryResult
from models.widget import WidgetAssessment
from services.platform_detector import PlatformDetectionResult
from services.url_validator import ValidationResult

REPORT_SCHEMA_VERSION = "1.0"


class CompatibilityStatus(str, Enum):
    GOOD_CANDIDATE = "Good candidate"
    REQUIRES_CLIENT_ACCESS = "Requires client access"
    PARTIALLY_COMPATIBLE = "Partially compatible"
    NOT_SUPPORTED = "Not currently supported"
    INCOMPLETE = "Assessment incomplete"


class StepStatus(str, Enum):
    COMPLETED = "completed"
    PARTIAL = "partial"      # ran, but the result is degraded (e.g. blocked probes)
    SKIPPED = "skipped"      # a prerequisite failed
    FAILED = "failed"        # unexpected internal error (caught by the error boundary)


class StepResult(BaseModel):
    name: str
    status: StepStatus
    duration_ms: int = 0
    detail: str | None = None


class Compatibility(BaseModel):
    status: CompatibilityStatus
    rule: str = Field(description="ID of the decision rule that produced the status")
    reasons: list[str] = Field(default_factory=list)
    next_steps: list[str] = Field(default_factory=list)


class ProductData(BaseModel):
    discovery: SourceDiscoveryResult | None = None
    extraction: ExtractionResult | None = None


class AssessmentReport(BaseModel):
    report_schema_version: str = REPORT_SCHEMA_VERSION
    assessment_id: str
    generated_at: datetime
    duration_ms: int
    input_url: str
    compatibility: Compatibility
    target: ValidationResult
    platform: PlatformDetectionResult | None = None
    product_data: ProductData = Field(default_factory=ProductData)
    widget: WidgetAssessment | None = None
    steps: list[StepResult] = Field(default_factory=list)
