"""Source discovery + extraction against fake stores (no network)."""

from __future__ import annotations

import gzip
import json

import pytest

from models.product import Product, compute_field_coverage
from models.source import SourceType
from services.product_extractor import extract_products, map_shopify_product, map_woo_product
from services.source_detector import discover_sources
from tests.conftest import PUBLIC_IP, FakeResponse

HTML = {"Content-Type": "text/html; charset=utf-8"}
JSON = {"Content-Type": "application/json"}
XML = {"Content-Type": "application/xml"}


def not_found():
    return FakeResponse(404, HTML, b"<html><title>404</title></html>")


def page(body: str, status: int = 200) -> FakeResponse:
    return FakeResponse(status, HTML, body.encode())


def jsonr(data, status: int = 200) -> FakeResponse:
    return FakeResponse(status, JSON, json.dumps(data).encode())


def xml(body: str) -> FakeResponse:
    return FakeResponse(200, XML, body.encode())


def sources_by_type(discovery):
    out = {}
    for s in discovery.sources:
        out.setdefault(s.source_type, []).append(s)
    return out


@pytest.fixture
def store(fake_dns, fake_http):
    fake_dns["shop.example.com"] = [PUBLIC_IP]
    fake_http.default = not_found
    return fake_http


# ---------------------------------------------------------------- Shopify
SHOPIFY_HOME = """<html><head><meta name="shopify-checkout-api-token" content="0123456789abcdef0123456789abcdef">
<script src="https://cdn.shopify.com/s/files/theme.js"></script><script>Shopify.shop = "x.myshopify.com";</script>
</head><body><div class="shopify-section"></div></body></html>"""


def shopify_products(n):
    return {"products": [{
        "title": f"Tee {i}", "handle": f"tee-{i}", "body_html": "<p>Soft <b>cotton</b></p>", "vendor": "Acme",
        "product_type": "Shirts" if i % 2 else "", "tags": ["summer", "cotton"],
        "options": [{"name": "Size", "values": ["S", "M"]}],
        "variants": [{"price": "25.00", "sku": f"T{i}", "available": i != 2}, {"price": "27.00", "available": False}],
        "images": [{"src": f"https://cdn.shopify.com/tee{i}.jpg"}],
    } for i in range(n)]}


def test_shopify_store_discovery_and_extraction(store):
    store["https://shop.example.com/"] = page(SHOPIFY_HOME, 200)
    store["https://shop.example.com/products.json?limit=5"] = jsonr(shopify_products(7))
    store["https://shop.example.com/robots.txt"] = FakeResponse(200, {"Content-Type": "text/plain"},
                                                                b"User-agent: *\nSitemap: https://shop.example.com/sitemap.xml\n")
    store["https://shop.example.com/sitemap.xml"] = xml(
        '<?xml version="1.0"?><sitemapindex xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">'
        '<sitemap><loc>https://shop.example.com/sitemap_pages_1.xml</loc></sitemap>'
        '<sitemap><loc>https://shop.example.com/sitemap_products_1.xml?from=1&amp;to=9</loc></sitemap></sitemapindex>')
    store["https://shop.example.com/sitemap_products_1.xml?from=1&to=9"] = xml(
        '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9"><url><loc>https://shop.example.com/</loc></url>'
        '<url><loc>https://shop.example.com/products/tee-0</loc></url></urlset>')

    home, platform, discovery, extraction = extract_products("https://shop.example.com")
    assert platform.detected_platform.value == "shopify"
    by = sources_by_type(discovery)

    api = by[SourceType.SHOPIFY_PRODUCTS_JSON][0]
    assert api.accessible and not api.requires_auth and api.item_count == 7
    assert any("currency" in lim for lim in api.limitations)

    sf = by[SourceType.SHOPIFY_STOREFRONT_API][0]
    assert sf.requires_auth and not sf.accessible
    assert "0123456789abcdef" not in json.dumps(sf.model_dump())     # token never leaked

    ps = by[SourceType.PRODUCT_SITEMAP][0]
    assert ps.accessible and ps.sample_urls == ["https://shop.example.com/products/tee-0"]   # homepage URL filtered out

    assert discovery.recommended_source == SourceType.SHOPIFY_PRODUCTS_JSON
    assert extraction.source_type == "shopify_products_json"
    assert extraction.items_extracted == 5                       # capped at 5 of 7
    p0, p2 = extraction.products[0], extraction.products[2]
    assert p0.currency is None                                   # not in products.json -> never invented
    assert p0.price == 25.0 and p0.description == "Soft cotton"
    assert p0.availability == "InStock" and p2.availability == "OutOfStock"
    assert p0.category is None and extraction.products[1].category == "Shirts"   # "" -> None
    assert p0.product_url == "https://shop.example.com/products/tee-0"
    assert p0.specifications["options"] == {"Size": ["S", "M"]}
    cov = extraction.field_coverage
    assert cov["name"] == 100.0 and cov["currency"] == 0.0 and cov["category"] == 40.0


def test_shopify_password_protected(store):
    store["https://shop.example.com/"] = page(SHOPIFY_HOME)
    store["https://shop.example.com/products.json?limit=5"] = FakeResponse(302, {"Location": "/password"})
    store["https://shop.example.com/password"] = page("<html>Password</html>")
    _, _, discovery, _ = discover_sources("https://shop.example.com")
    api = sources_by_type(discovery)[SourceType.SHOPIFY_PRODUCTS_JSON][0]
    assert not api.accessible and "password" in api.limitations[0].lower()


# ---------------------------------------------------------------- WooCommerce
WOO_HOME = """<html><head><meta name="generator" content="WooCommerce 9.1">
<link rel="stylesheet" href="/wp-content/plugins/woocommerce/assets/css/wc.css"></head>
<body class="woocommerce-page"></body></html>"""

WOO_ITEMS = [{
    "id": 1, "name": "Speckled Mug &#8211; Large", "permalink": "https://shop.example.com/product/mug/", "sku": "MUG",
    "short_description": "<p>Glazed</p>", "description": "<p>Long</p>",
    "prices": {"price": "1800", "currency_code": "GBP", "currency_minor_unit": 2},
    "is_in_stock": True, "is_on_backorder": False,
    "categories": [{"id": 3, "name": "Mugs"}], "images": [{"src": "https://shop.example.com/m.jpg"}],
    "attributes": [{"name": "Colour", "terms": [{"name": "Blue"}, {"name": "Green"}]}],
}, {
    "id": 2, "name": "No Price Bowl", "permalink": "https://shop.example.com/product/bowl/",
    "prices": {"price": "", "currency_code": "GBP", "currency_minor_unit": 2}, "is_in_stock": False,
}, {"id": 3, "name": "", "prices": {}}]


def test_woocommerce_store(store):
    store["https://shop.example.com/"] = page(WOO_HOME)
    store["https://shop.example.com/wp-json/wc/store/v1/products?per_page=5"] = jsonr(WOO_ITEMS)
    _, platform, discovery, extraction = extract_products("shop.example.com")
    assert platform.detected_platform.value == "woocommerce"
    assert discovery.recommended_source == SourceType.WOOCOMMERCE_STORE_API
    assert extraction.items_extracted == 2
    assert any("no product name" in w for w in extraction.warnings)
    mug, bowl = extraction.products
    assert (mug.name, mug.price, mug.currency, mug.availability) == ("Speckled Mug – Large", 18.0, "GBP", "InStock")
    assert mug.specifications == {"sku": "MUG", "Colour": ["Blue", "Green"]}
    assert (bowl.price, bowl.currency, bowl.availability) == (None, None, "OutOfStock")


def test_woo_legacy_path_and_auth_detection(store):
    store["https://shop.example.com/"] = page(WOO_HOME)
    store["https://shop.example.com/wp-json/wc/store/products?per_page=5"] = jsonr(
        {"code": "rest_forbidden", "message": "Sorry"}, 401)
    _, _, discovery, _ = discover_sources("shop.example.com")
    woo = sources_by_type(discovery)[SourceType.WOOCOMMERCE_STORE_API][0]
    assert not woo.accessible


def test_403_is_not_assumed_to_be_auth(store):
    store["https://shop.example.com/"] = page(WOO_HOME)
    store["https://shop.example.com/wp-json/wc/store/v1/products?per_page=5"] = FakeResponse(403, HTML, b"denied")
    _, _, discovery, _ = discover_sources("shop.example.com")
    woo = sources_by_type(discovery)[SourceType.WOOCOMMERCE_STORE_API][0]
    assert not woo.accessible and woo.requires_auth is False
    assert "may require authentication" in woo.limitations[0]


def test_401_marks_requires_auth(store):
    store["https://shop.example.com/"] = page(WOO_HOME)
    store["https://shop.example.com/wp-json/wc/store/v1/products?per_page=5"] = jsonr({"code": "rest_forbidden"}, 401)
    _, _, discovery, _ = discover_sources("shop.example.com")
    assert sources_by_type(discovery)[SourceType.WOOCOMMERCE_STORE_API][0].requires_auth is True


# ---------------------------------------------------------------- Custom store
PRODUCT_PAGE = """<html><head><script type="application/ld+json">{{"@context":"https://schema.org","@type":"Product",
"name":"{name}","offers":{{"@type":"Offer","price":"{price}","priceCurrency":"EUR","availability":"https://schema.org/InStock"}}}}</script>
</head></html>"""


def test_custom_store_via_sitemap_and_product_pages(store):
    store["https://shop.example.com/"] = page("<html><body><h1>Welcome</h1></body></html>")
    store["https://shop.example.com/sitemap.xml"] = xml(
        '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">'
        '<url><loc>https://shop.example.com/about</loc></url>'
        '<url><loc>https://shop.example.com/product/a</loc></url>'
        '<url><loc>https://shop.example.com/product/b</loc></url>'
        '<url><loc>https://shop.example.com/product/c</loc></url></urlset>')
    store["https://shop.example.com/product/a"] = page(PRODUCT_PAGE.format(name="Alpha", price="10.00"))
    store["https://shop.example.com/product/b"] = page("<html><body>No structured data, $99</body></html>")
    store["https://shop.example.com/product/c"] = page(PRODUCT_PAGE.format(name="Gamma", price="1.299,00"))

    _, platform, discovery, extraction = extract_products("https://shop.example.com/")
    assert discovery.recommended_source == SourceType.SITEMAP
    assert extraction.source_type == "sitemap"
    assert [p.name for p in extraction.products] == ["Alpha", "Gamma"]
    assert extraction.products[1].price == 1299.0
    assert any("no schema.org Product" in w for w in extraction.warnings)
    assert "https://shop.example.com/about" not in sources_by_type(discovery)[SourceType.SITEMAP][0].sample_urls


def test_html_product_links_source(store):
    store["https://shop.example.com/shop/"] = page(
        '<a href="/shop/alpha/">A</a><a href="/shop/page/2/">next</a><a href="/shop/?add-to-cart=5">add</a>'
        '<a href="https://other.example.net/shop/x/">ext</a><a href="/cart/">cart</a>')
    store["https://shop.example.com/shop/alpha/"] = page(PRODUCT_PAGE.format(name="Alpha", price="5"))
    _, _, discovery, extraction = extract_products("https://shop.example.com/shop/")
    html_src = sources_by_type(discovery)[SourceType.HTML_PRODUCT_PAGES][0]
    assert html_src.sample_urls == ["https://shop.example.com/shop/alpha/"]
    assert extraction.source_type == "html_product_pages" and extraction.products[0].name == "Alpha"


def test_gzipped_sitemap(store):
    store["https://shop.example.com/"] = page("<html></html>")
    store["https://shop.example.com/robots.txt"] = FakeResponse(
        200, {"Content-Type": "text/plain"}, b"Sitemap: /sitemap.xml.gz")
    body = gzip.compress(b'<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">'
                         b'<url><loc>https://shop.example.com/products/z</loc></url></urlset>')
    store["https://shop.example.com/sitemap.xml.gz"] = FakeResponse(200, {"Content-Type": "application/x-gzip"}, body)
    _, _, discovery, _ = discover_sources("https://shop.example.com/")
    gz = [s for s in discovery.sources if s.source_url.endswith(".gz")][0]
    assert gz.accessible and gz.sample_urls == ["https://shop.example.com/products/z"]


# ---------------------------------------------------------------- Priority & fallback
def test_api_beats_jsonld_and_falls_back_when_empty(store):
    home = SHOPIFY_HOME.replace("</head>", '<script type="application/ld+json">{"@type":"Product","name":"LD Item"}</script></head>')
    store["https://shop.example.com/"] = page(home)
    store["https://shop.example.com/products.json?limit=5"] = jsonr({"products": [{"title": ""}]})  # no valid items
    _, _, discovery, extraction = extract_products("https://shop.example.com/")
    assert discovery.recommended_source == SourceType.SHOPIFY_PRODUCTS_JSON
    assert [a.source_type for a in extraction.attempts] == ["shopify_products_json", "json_ld"]
    assert extraction.attempts[0].products_extracted == 0
    assert extraction.source_type == "json_ld" and extraction.products[0].name == "LD Item"


def test_no_sources_found(store):
    store["https://shop.example.com/"] = page("<html><body>Hello</body></html>")
    _, _, discovery, extraction = extract_products("https://shop.example.com/")
    assert discovery.recommended_source is None
    assert extraction.products == [] and extraction.items_extracted == 0
    assert "No accessible product data source was found." in extraction.warnings


# ---------------------------------------------------------------- SSRF through discovered URLs
def test_robots_sitemap_pointing_to_metadata_is_blocked(store):
    store["https://shop.example.com/"] = page("<html></html>")
    store["https://shop.example.com/robots.txt"] = FakeResponse(
        200, {"Content-Type": "text/plain"},
        b"Sitemap: http://169.254.169.254/latest/meta-data/\nSitemap: http://localhost/sitemap.xml\n")
    _, _, discovery, _ = discover_sources("https://shop.example.com/")
    assert not any("169.254" in c or "localhost" in c for c in store.calls)       # never requested
    blocked = [p for p in discovery.probes if p.error_code in ("unsafe_target", "invalid_url")]
    assert len(blocked) == 2
    meta_src = [s for s in discovery.sources if "169.254" in s.source_url][0]
    assert not meta_src.accessible and "SSRF" in meta_src.limitations[0]


def test_sitemap_entries_pointing_to_internal_hosts_are_blocked(store, fake_dns):
    fake_dns["internal.example.com"] = ["10.0.0.5"]
    store["https://shop.example.com/"] = page("<html></html>")
    store["https://shop.example.com/sitemap.xml"] = xml(
        '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">'
        '<url><loc>http://127.0.0.1/products/a</loc></url>'
        '<url><loc>https://internal.example.com/products/b</loc></url></urlset>')
    _, _, _, extraction = extract_products("https://shop.example.com/")
    assert not any("127.0.0.1" in c or "internal.example.com" in c for c in store.calls)
    assert extraction.products == []


def test_xxe_sitemap_rejected(store):
    store["https://shop.example.com/"] = page("<html></html>")
    store["https://shop.example.com/sitemap.xml"] = xml(
        '<?xml version="1.0"?><!DOCTYPE x [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>'
        '<urlset><url><loc>&xxe;</loc></url></urlset>')
    _, _, discovery, _ = discover_sources("https://shop.example.com/")
    sm = sources_by_type(discovery)[SourceType.SITEMAP][0]
    assert not sm.accessible and "parsed safely" in sm.limitations[0]


def test_billion_laughs_sitemap_rejected(store):
    store["https://shop.example.com/"] = page("<html></html>")
    store["https://shop.example.com/sitemap.xml"] = xml(
        '<?xml version="1.0"?><!DOCTYPE lolz [<!ENTITY lol "lol"><!ENTITY lol2 "&lol;&lol;&lol;&lol;">]>'
        '<urlset><url><loc>&lol2;</loc></url></urlset>')
    _, _, discovery, _ = discover_sources("https://shop.example.com/")
    assert not sources_by_type(discovery)[SourceType.SITEMAP][0].accessible


def test_html_soft_404_sitemap(store):
    store["https://shop.example.com/"] = page("<html></html>")
    store["https://shop.example.com/sitemap.xml"] = page("<!DOCTYPE html><html>Not here</html>")
    _, _, discovery, _ = discover_sources("https://shop.example.com/")
    assert "soft 404" in sources_by_type(discovery)[SourceType.SITEMAP][0].limitations[0]


def test_unsafe_submitted_url_makes_no_requests(store):
    home, platform, discovery, extraction = extract_products("http://169.254.169.254/")
    assert home.result.error_code.value == "unsafe_target"
    assert platform is None and discovery.sources == [] and extraction.products == []
    assert store.calls == []


# ---------------------------------------------------------------- mappers & coverage
def test_shopify_mapper_missing_available_flag_gives_null():
    p = map_shopify_product({"title": "X", "variants": [{"price": "1.00"}]}, "https://s.example.com")
    assert p.availability is None and p.price == 1.0 and p.currency is None


def test_shopify_mapper_default_title_option_dropped():
    p = map_shopify_product({"title": "X", "options": [{"name": "Title", "values": ["Default Title"]}]}, "https://s.example.com")
    assert "options" not in p.specifications


def test_woo_mapper_bad_minor_unit_gives_null_price():
    p = map_woo_product({"name": "X", "prices": {"price": "1800", "currency_code": "GBP"}}, "https://s.example.com")
    assert p.price is None and p.currency is None


def test_woo_mapper_missing_stock_flag_gives_null():
    assert map_woo_product({"name": "X"}, "https://s.example.com").availability is None


def test_field_coverage():
    items = [Product(name="A", price=1.0, specifications={"k": "v"}), Product(name="B"), Product(name="C", price=2.0),
             Product(name="D")]
    cov = compute_field_coverage(items)
    assert cov["name"] == 100.0 and cov["price"] == 50.0 and cov["specifications"] == 25.0 and cov["currency"] == 0.0
    assert set(cov) == {"name", "description", "price", "currency", "category", "specifications",
                        "image_url", "product_url", "availability"}


def test_field_coverage_empty():
    assert set(compute_field_coverage([]).values()) == {0.0}


def test_product_schema_is_strict():
    with pytest.raises(Exception):
        Product(name="X", rating=5)                    # extra field
    with pytest.raises(Exception):
        Product(name="X", currency="usd")              # must be upper ISO-4217
    with pytest.raises(Exception):
        Product(name="X", availability="Maybe")
    with pytest.raises(Exception):
        Product(name="X", image_url="javascript:alert(1)")
