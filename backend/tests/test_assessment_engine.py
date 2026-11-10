from __future__ import annotations

import json

import pytest
from fastapi.testclient import TestClient

from database.models import Platform
from main import app
from models.product import ExtractionResult, Product, compute_field_coverage
from models.report import CompatibilityStatus, StepResult, StepStatus
from models.source import DiscoveredSource, ProbeRecord, SourceDiscoveryResult, SourceType
from models.widget import CSPAnalysis, Feasibility, InstallationOption, InstallMethod, WidgetAssessment
from services import assessment_engine as engine
from services.assessment_engine import decide_compatibility, run_assessment
from services.platform_detector import Confidence, PlatformDetectionResult
from services.url_validator import ErrorCode, ValidationResult
from tests.conftest import PUBLIC_IP, FakeResponse
from tests.test_sources_and_extraction import SHOPIFY_HOME, shopify_products

S = CompatibilityStatus


# ------------------------------------------------------------------ builders for the decision table
def target(status=200, error_code=None):
    return ValidationResult(original_url="https://s.example.com", final_url="https://s.example.com/",
                            http_status=status, is_accessible=status == 200, error_code=error_code)


def plat(name="shopify", conf="high"):
    return PlatformDetectionResult(detected_platform=Platform(name), confidence=Confidence(conf), evidence=[], scores={})


def disc(sources=(), probes=()):
    return SourceDiscoveryResult(base_url="https://s.example.com", platform="shopify",
                                 sources=list(sources), probes=list(probes))


def extr(n=5, price=True, source="shopify_products_json"):
    products = [Product(name=f"P{i}", price=10.0 if price else None) for i in range(n)]
    return ExtractionResult(source_type=source if n else None, products=products, items_extracted=n,
                            field_coverage=compute_field_coverage(products))


def widget(method=InstallMethod.CMS_PLUGIN_APP, feas=Feasibility.LIKELY, csp="no_csp"):
    opt = InstallationOption(method=method, feasibility=feas, client_action_required="Do X.")
    return WidgetAssessment(recommended_method=method, options=[opt], csp=CSPAnalysis(verdict=csp))


def decide(t=None, p=None, d=None, e=None, w=None, steps=()):
    return decide_compatibility(t or target(), p if p is not None else plat(), d or disc(),
                                e if e is not None else extr(), w if w is not None else widget(), list(steps))


# ------------------------------------------------------------------ decision table: one test per rule
def test_r1_unsafe_url():
    c = decide(t=ValidationResult(original_url="x", error_code=ErrorCode.UNSAFE_TARGET, error="blocked"))
    assert (c.status, c.rule) == (S.INCOMPLETE, "R1")


def test_r1_unreachable():
    c = decide(t=ValidationResult(original_url="x", error_code=ErrorCode.DNS_FAILURE, error="nope"))
    assert (c.status, c.rule) == (S.INCOMPLETE, "R1")


def test_r2_internal_failure():
    c = decide(steps=[StepResult(name="source_discovery", status=StepStatus.FAILED)])
    assert (c.status, c.rule) == (S.INCOMPLETE, "R2") and "source_discovery" in c.reasons[0]


def test_r3_http_error():
    assert decide(t=target(status=500, error_code=ErrorCode.HTTP_ERROR)).rule == "R3"


def test_r4_platform_known_but_products_blocked_by_cloudflare():
    probes = [ProbeRecord(url="https://s.example.com/products.json", purpose="x", http_status=403,
                          error_code="bot_protection")]
    c = decide(d=disc(probes=probes), e=extr(0))
    assert (c.status, c.rule) == (S.INCOMPLETE, "R4")
    assert any("shopify" in r for r in c.reasons)          # what we did learn is still reported


def test_r4_time_budget():
    c = decide(d=disc(probes=[ProbeRecord(url="u", purpose="x", error_code="skipped_time_budget")]), e=extr(0))
    assert c.rule == "R4"


def test_r5_requires_auth_source():
    src = DiscoveredSource(source_type=SourceType.WOOCOMMERCE_STORE_API, source_url="u", accessible=False,
                           requires_auth=True, priority=1)
    c = decide(p=plat("custom", "medium"), d=disc([src]), e=extr(0))
    assert (c.status, c.rule) == (S.REQUIRES_CLIENT_ACCESS, "R5")


def test_r5_known_platform_without_public_catalog():
    assert decide(p=plat("magento"), e=extr(0)).rule == "R5"


def test_r6_no_data_unknown_platform():
    c = decide(p=plat("unknown", "low"), e=extr(0))
    assert (c.status, c.rule) == (S.NOT_SUPPORTED, "R6")


def test_r7_no_confirmed_install_route():
    c = decide(w=widget(InstallMethod.AGENCY_HANDOFF, Feasibility.REQUIRES_INVESTIGATION))
    assert (c.status, c.rule) == (S.PARTIALLY_COMPATIBLE, "R7")


def test_r8_weak_product_data():
    c = decide(e=extr(5, price=False))
    assert (c.status, c.rule) == (S.PARTIALLY_COMPATIBLE, "R8")


def test_r9_good_candidate():
    c = decide()
    assert (c.status, c.rule) == (S.GOOD_CANDIDATE, "R9") and c.next_steps == ["Do X."]


def test_r9_gtm_counts_as_self_serve():
    assert decide(w=widget(InstallMethod.GOOGLE_TAG_MANAGER)).rule == "R9"


def test_r10_script_tag_needs_access():
    c = decide(w=widget(InstallMethod.SCRIPT_TAG))
    assert (c.status, c.rule) == (S.REQUIRES_CLIENT_ACCESS, "R10")


def test_r10_csp_blocks_even_with_app():
    c = decide(w=widget(InstallMethod.CMS_PLUGIN_APP, Feasibility.POSSIBLE, csp="blocks"))
    assert c.rule == "R10" and any("Content-Security-Policy" in r for r in c.reasons)


def test_page_sampled_source_adds_caveat():
    c = decide(e=extr(5, source="product_sitemap"))
    assert "individual product pages" in c.reasons[0]


# ------------------------------------------------------------------ end-to-end orchestrator
@pytest.fixture
def shopify_store(fake_dns, fake_http):
    fake_dns["shop.example.com"] = [PUBLIC_IP]
    fake_http.default = lambda: FakeResponse(404, {"Content-Type": "text/html"}, b"nope")
    fake_http["https://shop.example.com/"] = FakeResponse(200, {"Content-Type": "text/html"}, SHOPIFY_HOME.encode())
    fake_http["https://shop.example.com/products.json?limit=5"] = FakeResponse(
        200, {"Content-Type": "application/json"}, json.dumps(shopify_products(3)).encode())
    return fake_http


def test_full_assessment_good_candidate(shopify_store):
    r = run_assessment("shop.example.com")
    assert r.compatibility.status == S.GOOD_CANDIDATE
    assert [s.name for s in r.steps] == ["validation", "platform_detection", "source_discovery",
                                         "product_extraction", "widget_assessment", "compatibility"]
    assert all(s.status == StepStatus.COMPLETED for s in r.steps)
    assert r.platform.detected_platform == Platform.SHOPIFY
    assert r.product_data.extraction.items_extracted == 3
    assert r.widget.recommended_method == InstallMethod.CMS_PLUGIN_APP
    assert r.report_schema_version == "1.0" and r.assessment_id
    # probes made during extraction are included in the discovery log
    assert any("products.json" in p.url for p in r.product_data.discovery.probes)


def test_unsafe_url_skips_everything(fake_dns, fake_http):
    r = run_assessment("http://169.254.169.254/latest/meta-data/")
    assert r.compatibility.rule == "R1"
    assert [s.status for s in r.steps[1:5]] == [StepStatus.SKIPPED] * 4
    assert fake_http.calls == []


@pytest.mark.parametrize("target_fn", ["discover_from_home", "extract_from_discovery",
                                       "assess_widget_installation", "detect_platform"])
def test_error_boundary_contains_step_failures(shopify_store, monkeypatch, caplog, target_fn):
    def boom(*a, **k):
        raise RuntimeError("secret internal detail")
    monkeypatch.setattr(engine, target_fn, boom)
    r = run_assessment("shop.example.com")                       # must not raise
    failed = [s for s in r.steps if s.status == StepStatus.FAILED]
    assert len(failed) == 1 and failed[0].detail == "Internal error (RuntimeError); step aborted."
    assert "secret internal detail" not in r.model_dump_json()  # internals not leaked to the client
    assert r.compatibility.status == S.INCOMPLETE and r.compatibility.rule == "R2"
    assert "secret internal detail" in caplog.text               # but logged server-side


def test_extraction_skipped_when_discovery_fails(shopify_store, monkeypatch):
    monkeypatch.setattr(engine, "discover_from_home", lambda *a, **k: 1 / 0)
    r = run_assessment("shop.example.com")
    steps = {s.name: s.status for s in r.steps}
    assert steps["source_discovery"] == StepStatus.FAILED
    assert steps["product_extraction"] == StepStatus.SKIPPED
    assert steps["widget_assessment"] == StepStatus.COMPLETED   # independent steps still run
    assert r.widget is not None and r.platform is not None


def test_compatibility_step_failure_still_returns_report(shopify_store, monkeypatch):
    monkeypatch.setattr(engine, "decide_compatibility", lambda *a, **k: 1 / 0)
    r = run_assessment("shop.example.com")
    assert r.compatibility.status == S.INCOMPLETE


def test_bot_protected_homepage(fake_dns, fake_http):
    fake_dns["cf.example.com"] = [PUBLIC_IP]
    fake_http.default = lambda: FakeResponse(403, {"Content-Type": "text/html", "cf-mitigated": "challenge"},
                                             b"<title>Just a moment...</title>")
    r = run_assessment("https://cf.example.com/")
    assert r.compatibility.status == S.INCOMPLETE and r.compatibility.rule == "R4"
    assert r.widget.csp.verdict == "not_checked"
    assert {s.name: s.status for s in r.steps}["validation"] == StepStatus.PARTIAL


# ------------------------------------------------------------------ endpoint
def test_analyse_endpoint(shopify_store):
    with TestClient(app) as client:
        res = client.post("/api/assessment/analyse", json={"url": "https://shop.example.com"})
    assert res.status_code == 200
    body = res.json()
    assert body["compatibility"]["status"] == "Good candidate"
    assert set(body) >= {"report_schema_version", "assessment_id", "generated_at", "compatibility", "target",
                         "platform", "product_data", "widget", "steps"}


def test_analyse_endpoint_unsafe(fake_dns, fake_http):
    with TestClient(app) as client:
        res = client.post("/api/assessment/analyse", json={"url": "http://localhost/"})
    assert res.status_code == 400
    assert res.json()["compatibility"]["status"] == "Assessment incomplete"
