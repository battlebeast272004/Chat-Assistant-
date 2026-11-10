from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from main import app
from tests.conftest import PUBLIC_IP, FakeResponse
from tests.test_platform_detector import SHOPIFY_HTML


@pytest.fixture
def client():
    with TestClient(app) as c:
        yield c


def test_health(client):
    assert client.get("/health").json() == {"status": "healthy"}


@pytest.mark.parametrize("url", ["http://localhost/", "http://169.254.169.254/latest/meta-data/", "file:///etc/passwd"])
def test_validate_rejects_unsafe(client, url, fake_dns, fake_http):
    r = client.post("/api/assessment/validate", json={"url": url})
    assert r.status_code == 400
    body = r.json()
    assert body["is_accessible"] is False
    assert body["error_code"] in ("unsafe_target", "invalid_url")
    assert set(body) >= {"original_url", "final_url", "is_accessible", "http_status",
                         "page_title", "response_time_ms", "error"}


def test_validate_missing_url_is_422(client):
    assert client.post("/api/assessment/validate", json={}).status_code == 422


def test_validate_ok(client, fake_dns, fake_http):
    fake_dns["store.example.com"] = [PUBLIC_IP]
    fake_http["https://store.example.com/"] = FakeResponse(200, {"Content-Type": "text/html"}, b"<title>Shop</title>")
    r = client.post("/api/assessment/validate", json={"url": "https://store.example.com"})
    assert r.status_code == 200
    assert r.json()["page_title"] == "Shop"


def test_detect_platform_endpoint(client, fake_dns, fake_http):
    fake_dns["store.example.com"] = [PUBLIC_IP]
    fake_http["https://store.example.com/"] = FakeResponse(
        200, {"Content-Type": "text/html", "X-ShopId": "42"}, SHOPIFY_HTML.encode())
    r = client.post("/api/assessment/detect-platform", json={"url": "store.example.com"})
    assert r.status_code == 200
    body = r.json()
    assert body["validation"]["is_accessible"] is True
    assert body["platform"]["detected_platform"] == "shopify"
    assert body["platform"]["confidence"] == "high"


def test_detect_platform_unsafe_returns_400_without_detection(client, fake_dns, fake_http):
    r = client.post("/api/assessment/detect-platform", json={"url": "http://127.0.0.1/"})
    assert r.status_code == 400
    assert r.json()["platform"] is None


@pytest.mark.parametrize("endpoint", ["detect-sources", "extract-products"])
def test_stage3_endpoints_reject_unsafe(client, endpoint, fake_dns, fake_http):
    r = client.post(f"/api/assessment/{endpoint}", json={"url": "http://169.254.169.254/"})
    assert r.status_code == 400
    assert r.json()["discovery"]["sources"] == []
    assert fake_http.calls == []


def test_extract_products_endpoint(client, fake_dns, fake_http):
    fake_dns["store.example.com"] = [PUBLIC_IP]
    fake_http.default = lambda: FakeResponse(404, {"Content-Type": "text/html"}, b"nope")
    fake_http["https://store.example.com/"] = FakeResponse(200, {"Content-Type": "text/html"}, SHOPIFY_HTML.encode())
    fake_http["https://store.example.com/products.json?limit=5"] = FakeResponse(
        200, {"Content-Type": "application/json"},
        b'{"products":[{"title":"Tee","handle":"tee","variants":[{"price":"10.00","available":true}]}]}')
    r = client.post("/api/assessment/extract-products", json={"url": "store.example.com"})
    assert r.status_code == 200
    body = r.json()
    assert body["discovery"]["recommended_source"] == "shopify_products_json"
    ex = body["extraction"]
    assert ex["items_extracted"] == 1
    assert ex["products"][0] == {
        "name": "Tee", "description": None, "price": 10.0, "currency": None, "category": None,
        "specifications": {"variant_count": 1}, "image_url": None,
        "product_url": "https://store.example.com/products/tee", "availability": "InStock",
    }
    assert ex["field_coverage"]["price"] == 100.0 and ex["field_coverage"]["currency"] == 0.0
