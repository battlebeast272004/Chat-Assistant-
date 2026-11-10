"""Assessment orchestrator: runs every stage in order and builds the unified report.

Error boundaries
----------------
Each step runs inside ``_Step``. An unexpected exception is caught and logged
with its full traceback on the server. The step is marked ``failed`` in the
report with only the exception *type* (internals are never leaked), and later
steps that depend on it are marked ``skipped``. The orchestrator itself never
raises: a report is always returned.

Pipeline
--------
  1 validation          fetch the submitted URL through the SSRF-safe fetcher
  2 platform_detection  needs 1 (an HTTP response)
  3 source_discovery    needs 1; uses 2 if available (else probes as "unknown")
  4 product_extraction  needs 3
  5 widget_assessment   needs 1; uses 2 and 3 if available
  6 compatibility       always runs (pure function of the above)

Compatibility decision table (first matching rule wins; the rule ID is in the report):

  R1  URL invalid/unsafe, or no HTTP response                -> Assessment incomplete
  R2  a core step failed with an internal error              -> Assessment incomplete
  R3  homepage returned HTTP >= 400 (not bot protection)     -> Assessment incomplete
  R4  no products AND bot protection / time budget hit       -> Assessment incomplete
  R5  no products AND an authenticated source exists, or
      a known platform whose public catalog is unavailable   -> Requires client access
  R6  no products (custom/unknown platform)                  -> Not currently supported
  R7  products, but no install route better than
      requires_investigation                                 -> Partially compatible
  R8  products, but weak data (name < 100% or price < 80%)   -> Partially compatible
  R9  products + self-serve route (app/plugin or GTM) is
      'likely' and CSP doesn't block                         -> Good candidate
  R10 products + install needs template/code/CSP access      -> Requires client access
"""

from __future__ import annotations

import logging
import time
import uuid
from datetime import datetime, timezone
from typing import Any, Callable

from database.models import Platform
from models.product import ExtractionResult
from models.report import (
    AssessmentReport,
    Compatibility,
    CompatibilityStatus,
    ProductData,
    StepResult,
    StepStatus,
)
from models.source import PAGE_SAMPLING, SourceDiscoveryResult
from models.widget import Feasibility, InstallMethod, WidgetAssessment
from services.platform_detector import PlatformDetectionResult, detect_platform
from services.product_extractor import extract_from_discovery
from services.source_detector import ProbeContext, discover_from_home
from services.url_validator import CLIENT_ERROR_CODES, ErrorCode, FetchResult, ValidationResult
from services.widget_checker import assess_widget_installation

logger = logging.getLogger("assessment.engine")

GOOD_PRICE_COVERAGE = 80.0
PAGE_SAMPLED = {s.value for s in PAGE_SAMPLING}
SELF_SERVE_METHODS = {InstallMethod.CMS_PLUGIN_APP, InstallMethod.GOOGLE_TAG_MANAGER}
KNOWN_PLATFORMS = {Platform.SHOPIFY.value, Platform.WOOCOMMERCE.value, Platform.MAGENTO.value,
                   Platform.BIGCOMMERCE.value, Platform.WIX.value}


class _Step:
    """Runs one pipeline step, records its timing and status, and contains failures."""

    def __init__(self, name: str, steps: list[StepResult], on_step: Callable[[str], None] | None = None):
        self.name, self.steps, self.on_step = name, steps, on_step

    def run(self, fn: Callable[[], Any], *, partial_if: Callable[[Any], str | None] | None = None) -> Any:
        if self.on_step:
            try:
                self.on_step(self.name)
            except Exception:  # progress reporting must never break the assessment
                logger.exception("Progress callback failed for step %s", self.name)
        started = time.monotonic()
        try:
            result = fn()
        except Exception as exc:  # error boundary
            logger.exception("Assessment step %s failed", self.name)
            self._record(StepStatus.FAILED, started, f"Internal error ({type(exc).__name__}); step aborted.")
            return None
        detail = partial_if(result) if partial_if else None
        self._record(StepStatus.PARTIAL if detail else StepStatus.COMPLETED, started, detail)
        return result

    def skip(self, reason: str) -> None:
        self.steps.append(StepResult(name=self.name, status=StepStatus.SKIPPED, detail=reason))

    def _record(self, status: StepStatus, started: float, detail: str | None) -> None:
        self.steps.append(StepResult(name=self.name, status=status,
                                     duration_ms=int((time.monotonic() - started) * 1000), detail=detail))


# ======================================================================
# Compatibility decision
# ======================================================================
def decide_compatibility(
    target: ValidationResult,
    platform: PlatformDetectionResult | None,
    discovery: SourceDiscoveryResult | None,
    extraction: ExtractionResult | None,
    widget: WidgetAssessment | None,
    steps: list[StepResult],
) -> Compatibility:
    def out(status: CompatibilityStatus, rule: str, reasons: list[str], next_steps: list[str]) -> Compatibility:
        return Compatibility(status=status, rule=rule, reasons=reasons, next_steps=next_steps)

    INC = CompatibilityStatus.INCOMPLETE

    # R1: never got a response
    if target.error_code in CLIENT_ERROR_CODES:
        return out(INC, "R1", [f"URL rejected: {target.error}"], ["Submit a valid, public http(s) store URL."])
    if target.http_status is None:
        return out(INC, "R1", [f"Site could not be reached: {target.error or 'unknown error'}"],
                   ["Check the URL is correct and the site is online, then re-run."])

    # R2: internal failure in a core step
    failed = [s.name for s in steps if s.status == StepStatus.FAILED]
    if failed:
        return out(INC, "R2", [f"Internal error in step(s): {', '.join(failed)}."],
                   ["Re-run the assessment; if it fails again, report the assessment ID."])

    # R3: homepage error that isn't bot protection
    if target.http_status >= 400 and target.error_code != ErrorCode.BOT_PROTECTION:
        return out(INC, "R3", [f"Homepage responded with HTTP {target.http_status}."],
                   ["Confirm the store's public URL (e.g. the www vs non-www host)."])

    products = extraction.items_extracted if extraction else 0
    platform_name = platform.detected_platform.value if platform else Platform.UNKNOWN.value
    probes = discovery.probes if discovery else []
    bot_blocked = target.error_code == ErrorCode.BOT_PROTECTION or any(
        p.error_code == ErrorCode.BOT_PROTECTION.value for p in probes)
    out_of_time = any(p.error_code == "skipped_time_budget" for p in probes)

    if products == 0:
        # R4: we couldn't look properly, so don't conclude anything
        if bot_blocked or out_of_time:
            why = "bot protection blocked one or more requests" if bot_blocked else "the time budget ran out"
            reasons = [f"No products could be extracted because {why}."]
            if platform and platform_name != Platform.UNKNOWN.value:
                reasons.append(f"Platform was identified as {platform_name} ({platform.confidence.value} confidence).")
            return out(INC, "R4", reasons,
                       ["Ask the client to allowlist our assessment User-Agent, or re-run with browser-based "
                        "inspection (Stage 5).", "Alternatively request product API credentials from the client."])
        auth_sources = [s for s in (discovery.sources if discovery else []) if s.requires_auth]
        # R5
        if auth_sources or platform_name in KNOWN_PLATFORMS:
            reasons = ["No product data is publicly accessible."]
            if auth_sources:
                reasons.append("Authenticated source(s) found: " + ", ".join(s.source_type.value for s in auth_sources) + ".")
            else:
                reasons.append(f"{platform_name} provides authenticated product APIs that the client can grant access to.")
            return out(CompatibilityStatus.REQUIRES_CLIENT_ACCESS, "R5", reasons,
                       [f"Request read-only product API credentials for the client's {platform_name} store."])
        # R6
        return out(CompatibilityStatus.NOT_SUPPORTED, "R6",
                   ["No public product data source with structured product data was found "
                    f"(platform: {platform_name})."],
                   ["Ask the client for a product feed (XML/CSV) or API access, or add schema.org Product "
                    "markup to product pages."])

    # Products exist from here on.
    cov = extraction.field_coverage if extraction else {}
    best = None
    if widget and widget.options:
        best = next((o for o in widget.options if o.method == widget.recommended_method), None)
    data_reason = f"{products} sample product(s) extracted from {extraction.source_type}."
    if extraction.source_type in PAGE_SAMPLED:
        data_reason += (" No public catalog API/feed was available, so ongoing ingestion would rely on "
                        "reading individual product pages.")

    # R7
    if best is None or best.feasibility == Feasibility.REQUIRES_INVESTIGATION:
        return out(CompatibilityStatus.PARTIALLY_COMPATIBLE, "R7",
                   [data_reason, "No widget installation route could be confirmed from public evidence."],
                   ["Review the widget options' evidence and risks with the client's technical contact."])
    # R8
    if cov.get("name", 0) < 100 or cov.get("price", 0) < GOOD_PRICE_COVERAGE:
        return out(CompatibilityStatus.PARTIALLY_COMPATIBLE, "R8",
                   [data_reason, f"Product data is incomplete (price coverage {cov.get('price', 0)}%)."],
                   ["Ask the client for a complete product feed or API access to fill in missing fields."])

    csp_ok = widget.csp.verdict not in ("blocks", "unclear")
    # R9
    if best.method in SELF_SERVE_METHODS and best.feasibility == Feasibility.LIKELY and csp_ok:
        return out(CompatibilityStatus.GOOD_CANDIDATE, "R9",
                   [data_reason, f"Self-serve installation likely via {best.method.value}."],
                   [best.client_action_required])
    # R10
    reasons = [data_reason]
    if not csp_ok:
        reasons.append("The site's Content-Security-Policy must be changed to allow the widget.")
    reasons.append(f"Best installation route ({best.method.value}, {best.feasibility.value}) needs template, "
                   "code or admin access that can't be verified publicly.")
    return out(CompatibilityStatus.REQUIRES_CLIENT_ACCESS, "R10", reasons, [best.client_action_required])


# ======================================================================
# Orchestrator
# ======================================================================
def run_assessment(raw_url: str, on_step: Callable[[str], None] | None = None) -> AssessmentReport:
    """Run the full pipeline. `on_step(name)` is called as each step starts (used for live progress)."""
    started = time.monotonic()
    steps: list[StepResult] = []
    ctx = ProbeContext()

    home: FetchResult | None = _Step("validation", steps, on_step).run(
        lambda: ctx.fetch(raw_url, "homepage"),
        partial_if=lambda h: (h.result.error or "No response") if h and not h.result.is_accessible else None,
    )
    target = home.result if home else ValidationResult(original_url=raw_url, error="Internal error during validation.")
    reachable = bool(home and target.http_status is not None and target.error_code not in CLIENT_ERROR_CODES)

    platform = discovery = extraction = widget = None

    s = _Step("platform_detection", steps, on_step)
    if reachable:
        platform = s.run(lambda: detect_platform(
            home.html, home.headers, home.cookie_names, target.final_url,
            blocked=target.error_code == ErrorCode.BOT_PROTECTION))
    else:
        s.skip("No HTTP response from the target.")

    s = _Step("source_discovery", steps, on_step)
    if reachable:
        discovery = s.run(
            lambda: discover_from_home(raw_url, home, platform, ctx),
            partial_if=lambda d: "Some probes were blocked or skipped." if any(
                p.error_code in (ErrorCode.BOT_PROTECTION.value, "skipped_time_budget") for p in d.probes) else None,
        )
    else:
        s.skip("No HTTP response from the target.")

    s = _Step("product_extraction", steps, on_step)
    if discovery is not None:
        extraction = s.run(lambda: extract_from_discovery(discovery, ctx),
                           partial_if=lambda e: None if e.items_extracted else "No products extracted.")
        if discovery is not None:
            discovery.probes = list(ctx.probes)  # include requests made during extraction
    else:
        s.skip("Source discovery did not complete.")

    s = _Step("widget_assessment", steps, on_step)
    if reachable:
        widget = s.run(lambda: assess_widget_installation(home, platform, discovery))
    else:
        s.skip("No HTTP response from the target.")

    s = _Step("compatibility", steps, on_step)
    compatibility = s.run(lambda: decide_compatibility(target, platform, discovery, extraction, widget, steps))
    if compatibility is None:
        compatibility = Compatibility(status=CompatibilityStatus.INCOMPLETE, rule="R2",
                                      reasons=["Internal error while computing compatibility."])

    return AssessmentReport(
        assessment_id=str(uuid.uuid4()),
        generated_at=datetime.now(timezone.utc),
        duration_ms=int((time.monotonic() - started) * 1000),
        input_url=raw_url,
        compatibility=compatibility,
        target=target,
        platform=platform,
        product_data=ProductData(discovery=discovery, extraction=extraction),
        widget=widget,
        steps=steps,
    )
