"""Stage 5: persistence, history/job routes, and hardening checks."""

from __future__ import annotations

import ast
import json
import re
import sqlite3
import time
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from database import connection as db
from database.models import AssessmentStatus
from main import app
from services import jobs
from services import url_validator as uv
from services.rate_limit import RateLimiter, assessment_limiter
from tests.conftest import PUBLIC_IP, FakeResponse
from tests.test_sources_and_extraction import SHOPIFY_HOME, shopify_products

BACKEND = Path(__file__).resolve().parents[1]


@pytest.fixture
def client():
    with TestClient(app) as c:
        yield c


@pytest.fixture
def shopify_store(fake_dns, fake_http):
    fake_dns["shop.example.com"] = [PUBLIC_IP]
    fake_http.default = lambda: FakeResponse(404, {"Content-Type": "text/html"}, b"nope")
    fake_http["https://shop.example.com/"] = lambda: FakeResponse(200, {"Content-Type": "text/html"}, SHOPIFY_HOME.encode())
    fake_http["https://shop.example.com/products.json?limit=5"] = lambda: FakeResponse(
        200, {"Content-Type": "application/json"}, json.dumps(shopify_products(2)).encode())
    return fake_http


def wait_for(client, assessment_id, timeout=10.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        body = client.get(f"/api/assessment/{assessment_id}").json()
        if body["status"] not in ("pending", "running"):
            return body
        time.sleep(0.05)
    raise AssertionError("assessment did not finish")


# ------------------------------------------------------------------ database helpers
def test_save_and_get_roundtrip():
    aid = db.create_assessment("https://a.example.com", "https://a.example.com/")
    db.update_progress(aid, "platform_detection")
    row = db.get_assessment(aid)
    assert row["status"] == "running" and row["current_step"] == "platform_detection"
    db.save_report(aid, status=AssessmentStatus.COMPLETED, report_json='{"x": 1}', platform="shopify",
                   compatibility_status="Good candidate", assessment_uuid="u-1", normalized_url=None,
                   report_schema_version="1.0")
    row = db.get_assessment(aid)
    assert row["status"] == "completed" and row["current_step"] is None and row["completed_at"]
    assert row["normalized_url"] == "https://a.example.com/"          # COALESCE keeps the original
    assert json.loads(row["report_json"]) == {"x": 1}


def test_history_pagination_newest_first():
    ids = [db.create_assessment(f"https://s{i}.example.com", None) for i in range(25)]
    rows, total, _ = db.list_assessments(page=1, page_size=10)
    assert total == 25 and [r["id"] for r in rows] == list(reversed(ids))[:10]
    rows3, _, _ = db.list_assessments(page=3, page_size=10)
    assert [r["id"] for r in rows3] == list(reversed(ids))[20:]
    assert db.list_assessments(page=99, page_size=10)[0] == []
    assert len(db.list_assessments(page=1, page_size=10_000)[0]) == 25   # clamped to MAX_PAGE_SIZE (100)


def test_sql_injection_payloads_are_stored_verbatim():
    payload = "https://x.example.com/'); DROP TABLE assessments;--"
    aid = db.create_assessment(payload, payload)
    assert db.get_assessment(aid)["url"] == payload
    assert db.list_assessments()[1] == 1                                # table still exists


def test_connection_module_never_formats_user_values_into_sql():
    """Static check: f-strings inside execute() may only interpolate module constants."""
    tree = ast.parse((BACKEND / "database" / "connection.py").read_text(encoding="utf-8"))
    allowed = {"_NOW", "_LIST_COLUMNS", "column", "sql_type"}   # constants / hard-coded migration names
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and getattr(node.func, "attr", None) == "execute" and node.args:
            for sub in ast.walk(node.args[0]):
                if isinstance(sub, ast.FormattedValue):
                    names = {n.id for n in ast.walk(sub.value) if isinstance(n, ast.Name)}
                    assert names <= allowed, f"user-controlled value formatted into SQL: {names}"


def test_migration_adds_new_columns_to_old_database(tmp_path, monkeypatch):
    path = tmp_path / "old.db"
    conn = sqlite3.connect(path)
    conn.execute("CREATE TABLE assessments (id INTEGER PRIMARY KEY AUTOINCREMENT, url TEXT NOT NULL, "
                 "normalized_url TEXT, platform TEXT, status TEXT NOT NULL DEFAULT 'pending', report_json TEXT, "
                 "report_schema_version TEXT NOT NULL DEFAULT '1.0', error_message TEXT, "
                 "created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')), "
                 "updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')), completed_at TEXT)")
    conn.commit()
    conn.close()
    monkeypatch.setattr(db, "DB_PATH", path)
    db.init_db()
    db.init_db()  # idempotent
    cols = {r[1] for r in sqlite3.connect(path).execute("PRAGMA table_info(assessments)")}
    assert {"compatibility_status", "assessment_uuid", "current_step"} <= cols


def test_interrupted_jobs_marked_failed():
    aid = db.create_assessment("https://a.example.com", None)
    db.update_progress(aid, "source_discovery")
    assert db.fail_interrupted_assessments() == 1
    row = db.get_assessment(aid)
    assert row["status"] == "failed" and "restart" in row["error_message"]


# ------------------------------------------------------------------ job flow + routes
def test_start_poll_and_history(client, shopify_store):
    r = client.post("/api/assessment/start", json={"url": "shop.example.com"})
    assert r.status_code == 202
    aid = r.json()["id"]
    done = wait_for(client, aid)
    assert done["status"] == "completed"
    assert done["compatibility_status"] == "Good candidate"
    assert done["platform"] == "shopify" and done["domain"] == "shop.example.com"
    assert done["report"]["compatibility"]["status"] == "Good candidate"
    assert len(done["report"]["product_data"]["extraction"]["products"]) == 2

    hist = client.get("/api/assessment/history").json()
    assert hist["total"] == 1 and hist["items"][0]["id"] == aid
    assert "report" not in hist["items"][0]                       # list stays lightweight
    assert hist["summary"] == {"Good candidate": 1}


def test_progress_steps_are_recorded(shopify_store, monkeypatch):
    seen = []
    real = db.update_progress
    monkeypatch.setattr(db, "update_progress", lambda i, s: (seen.append(s), real(i, s)))
    aid = jobs.submit("https://shop.example.com", "https://shop.example.com/")
    deadline = time.monotonic() + 10
    while db.get_assessment(aid)["status"] in ("pending", "running") and time.monotonic() < deadline:
        time.sleep(0.05)
    assert seen == ["validation", "platform_detection", "source_discovery", "product_extraction",
                    "widget_assessment", "compatibility"]


@pytest.mark.parametrize("url,code", [
    ("http://169.254.169.254/latest/meta-data/", "unsafe_target"),
    ("http://localhost:8000/", "invalid_url"),
    ("ftp://example.com", "invalid_url"),
])
def test_start_rejects_bad_urls_without_creating_rows(client, fake_dns, fake_http, url, code):
    r = client.post("/api/assessment/start", json={"url": url})
    assert r.status_code == 400 and r.json()["error_code"] == code
    assert client.get("/api/assessment/history").json()["total"] == 0
    assert fake_http.calls == []


def test_start_reports_unresolvable_domain(client, fake_dns, fake_http):
    r = client.post("/api/assessment/start", json={"url": "https://no-such-shop.example"})
    assert r.status_code == 400 and r.json()["error_code"] == "dns_failure"


def test_job_crash_marks_row_failed(client, shopify_store, monkeypatch):
    monkeypatch.setattr(jobs, "run_assessment", lambda *a, **k: 1 / 0)
    aid = client.post("/api/assessment/start", json={"url": "shop.example.com"}).json()["id"]
    done = wait_for(client, aid)
    assert done["status"] == "failed" and done["report"] is None
    assert "ZeroDivision" not in done["error_message"]


def test_queue_full_returns_429(client, shopify_store, monkeypatch):
    monkeypatch.setattr(jobs, "_outstanding", jobs.MAX_CONCURRENT_JOBS + jobs.MAX_QUEUED_JOBS)
    r = client.post("/api/assessment/start", json={"url": "shop.example.com"})
    assert r.status_code == 429
    monkeypatch.setattr(jobs, "_outstanding", 0)


def test_analyse_persists_and_returns_id_header(client, shopify_store):
    r = client.post("/api/assessment/analyse", json={"url": "shop.example.com"})
    assert r.status_code == 200
    aid = int(r.headers["X-Assessment-Id"])
    assert client.get(f"/api/assessment/{aid}").json()["report"]["assessment_id"] == r.json()["assessment_id"]


def test_analyse_does_not_store_rejected_urls(client, fake_dns, fake_http):
    assert client.post("/api/assessment/analyse", json={"url": "http://127.0.0.1/"}).status_code == 400
    assert client.get("/api/assessment/history").json()["total"] == 0


def test_get_unknown_and_invalid_ids(client):
    assert client.get("/api/assessment/999999").status_code == 404
    assert client.get("/api/assessment/abc").status_code == 422
    assert client.get("/api/assessment/0").status_code == 422
    assert client.get("/api/assessment/1; DROP TABLE assessments").status_code == 422


def test_history_query_validation(client):
    assert client.get("/api/assessment/history?page=0").status_code == 422
    assert client.get("/api/assessment/history?page_size=1000").status_code == 422


def test_failed_unreachable_row_status(client, fake_dns, fake_http):
    fake_dns["down.example.com"] = ["93.184.215.14"]
    fake_http["https://down.example.com/"] = __import__("requests").exceptions.ConnectionError()
    aid = client.post("/api/assessment/start", json={"url": "down.example.com"}).json()["id"]
    done = wait_for(client, aid)
    assert done["status"] == "failed" and done["compatibility_status"] == "Assessment incomplete"
    assert done["report"]["compatibility"]["rule"] == "R1"


# ------------------------------------------------------------------ rate limiting
def test_rate_limit(client, fake_dns, fake_http, monkeypatch):
    monkeypatch.setattr(assessment_limiter, "limit", 2)
    codes = [client.post("/api/assessment/validate", json={"url": "http://127.0.0.1/"}).status_code for _ in range(3)]
    assert codes == [400, 400, 429]


def test_rate_limiter_window():
    rl = RateLimiter(2, window_s=0.05)
    assert rl.allow("a") and rl.allow("a") and not rl.allow("a") and rl.allow("b")
    time.sleep(0.06)
    assert rl.allow("a")


# ------------------------------------------------------------------ security headers
def test_dashboard_security_headers(client):
    r = client.get("/")
    csp = r.headers["content-security-policy"]
    assert "script-src 'self'" in csp and "frame-ancestors 'none'" in csp and "unsafe-inline" not in csp
    assert r.headers["x-content-type-options"] == "nosniff"
    assert "content-security-policy" not in client.get("/docs").headers   # Swagger UI needs its CDN


def test_frontend_has_no_inline_script_or_handlers():
    html = (BACKEND.parent / "frontend" / "index.html").read_text(encoding="utf-8")
    assert not re.search(r"\son[a-z]+\s*=", html, re.I)                  # no onclick= etc.
    assert not re.search(r"<script(?![^>]*\bsrc=)[^>]*>", html, re.I)    # no inline <script>
    assert not re.search(r"\sstyle\s*=", html, re.I)                      # no inline style attributes


def test_frontend_never_uses_innerhtml():
    js = (BACKEND.parent / "frontend" / "script.js").read_text(encoding="utf-8")
    js = re.sub(r"/\*.*?\*/", "", js, flags=re.S)       # ignore comments
    js = re.sub(r"(?m)^\s*//.*$", "", js)
    for sink in ("innerHTML", "outerHTML", "insertAdjacentHTML", "document.write", "eval("):
        assert sink not in js


# ------------------------------------------------------------------ outbound request limits
def test_only_url_validator_performs_http():
    """Every outbound request must go through validate_target (SSRF + 10 s + 5 MB)."""
    offenders = []
    for path in (BACKEND / "services").glob("*.py"):
        if path.name == "url_validator.py":
            continue
        src = path.read_text(encoding="utf-8")
        for needle in ("import requests", "import httpx", "import urllib.request", "import socket",
                       "from requests", "from httpx", "urlopen(", "build_session("):
            if needle in src:
                offenders.append(f"{path.name}: {needle}")
    assert offenders == []


def test_timeout_and_size_cannot_be_raised_by_callers(fake_dns, fake_http):
    fake_dns["big.example.com"] = [PUBLIC_IP]
    captured = {}

    def send(session, url, timeout):
        captured["timeout"] = timeout
        return FakeResponse(200, {"Content-Type": "text/html"}, chunks=[b"x" * (1024 * 1024)] * 6)

    import services.url_validator as mod
    original = mod._send
    mod._send = send
    try:
        res = uv.validate_target("https://big.example.com/", timeout_s=999, max_bytes=10**12).result
    finally:
        mod._send = original
    assert res.error_code == uv.ErrorCode.RESPONSE_TOO_LARGE           # 5 MB cap still applied
    connect, read = captured["timeout"]
    assert connect <= uv.CONNECT_TIMEOUT_S and read <= uv.REQUEST_TIMEOUT_S


def test_limits_are_the_documented_values():
    assert uv.REQUEST_TIMEOUT_S == 10.0 and uv.MAX_RESPONSE_BYTES == 5 * 1024 * 1024 and uv.MAX_REDIRECTS == 5
