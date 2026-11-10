"""JSON-LD repair, graph walking and strict normalization (no fabrication)."""

from __future__ import annotations

import math

import pytest

from services.structured_data import (
    extract_jsonld,
    iter_product_nodes,
    normalize_availability,
    normalize_currency,
    parse_jsonld_text,
    parse_price,
    product_from_jsonld,
    product_from_opengraph,
    products_from_html,
    safe_url,
)

PAGE = "https://shop.example.com/products/mug"


def ld(*blocks: str) -> str:
    return "<html><head>" + "".join(f'<script type="application/ld+json">{b}</script>' for b in blocks) + "</head></html>"


# ------------------------------------------------------------------ malformed JSON-LD
@pytest.mark.parametrize("text", [
    '{"@type": "Product", "name": "Mug",}',                                   # trailing comma
    '<!-- {"@type": "Product", "name": "Mug"} -->',                           # HTML comment wrapper
    '//<![CDATA[\n{"@type": "Product", "name": "Mug"}\n//]]>',                # CDATA wrapper
    '/*<![CDATA[*/{"@type": "Product", "name": "Mug"}/*]]>*/',
    '﻿  {"@type": "Product", "name": "Mug"};',                           # BOM + trailing semicolon
    '{"@type": "Product", "name": "Mug", "description": "line1\nline2"}',      # raw newline in string
    '{"@type": "Product", "name": "Mug", "offers": [{"price": "1"},]}',      # trailing comma in array
])
def test_repairable_jsonld(text):
    values = parse_jsonld_text(text)
    assert values[0]["name"] == "Mug"


def test_concatenated_objects():
    values = parse_jsonld_text('{"@type":"Organization"}{"@type":"Product","name":"Mug"}')
    assert len(values) == 2 and values[1]["name"] == "Mug"


@pytest.mark.parametrize("text", [
    "",
    "   ",
    '{"@type": "Product", "name": }',
    "{'@type': 'Product'}",            # single quotes: not JSON, not guessed
    "not json at all",
    '{"@type": "Product", "name": "Mug"',  # truncated
])
def test_unrepairable_jsonld_raises(text):
    with pytest.raises(ValueError):
        parse_jsonld_text(text)


def test_malformed_block_skipped_with_warning_and_good_block_kept():
    html = ld('{"@type": "Product", "name": }', '{"@type": "Product", "name": "Good Mug"}')
    values, warnings = extract_jsonld(html)
    assert [v["name"] for v in values] == ["Good Mug"]
    assert warnings == ["1 JSON-LD block(s) could not be parsed and were skipped."]


def test_deeply_nested_jsonld_does_not_crash():
    deep = "[" * 5000 + "]" * 5000
    values, warnings = extract_jsonld(ld(deep, '{"@type":"Product","name":"Mug"}'))
    assert any(isinstance(v, dict) and v.get("name") == "Mug" for v in values)


def test_non_jsonld_scripts_ignored():
    html = '<script>var x = {"@type":"Product","name":"Nope"};</script>' + ld('{"@type":"Product","name":"Yes"}')
    values, _ = extract_jsonld(html)
    assert [v["name"] for v in values] == ["Yes"]


# ------------------------------------------------------------------ graph walking
def test_graph_itemlist_and_type_variants():
    values = parse_jsonld_text("""{
      "@context": "https://schema.org",
      "@graph": [
        {"@type": "Organization", "name": "Shop"},
        {"@type": ["Product", "Thing"], "name": "A"},
        {"@type": "ItemList", "itemListElement": [
          {"@type": "ListItem", "position": 1, "item": {"@type": "http://schema.org/Product", "name": "B"}},
          {"@type": "ListItem", "position": 2, "item": {"@type": "schema:Product", "name": "C"}}
        ]},
        {"@type": "WebPage", "mainEntity": {"@type": "ProductGroup", "name": "D",
           "hasVariant": [{"@type": "Product", "name": "D-red"}, {"@type": "Product", "name": "D-blue"}]}}
      ]}""")
    names = [n["name"] for n in iter_product_nodes(values)]
    assert names == ["A", "B", "C", "D"]          # variants are not emitted separately


def test_related_products_inside_product_not_emitted():
    values = parse_jsonld_text('{"@type":"Product","name":"Main","isRelatedTo":{"@type":"Product","name":"Other"}}')
    assert [n["name"] for n in iter_product_nodes(values)] == ["Main"]


# ------------------------------------------------------------------ value normalization
@pytest.mark.parametrize("raw,expected", [
    (19.99, 19.99), (0, 0.0), ("19.99", 19.99), ("$19.99", 19.99), ("19.99 USD", 19.99),
    ("1,299.00", 1299.0), ("1.299,00", 1299.0), ("19,99", 19.99), ("1 299.00", 1299.0),
    ("€ 1.299,50", 1299.5), ({"@value": "5.00"}, 5.0), ("1,299", 1299.0),
])
def test_parse_price_valid(raw, expected):
    assert parse_price(raw) == pytest.approx(expected)


@pytest.mark.parametrize("raw", [
    None, "", "  ", "Call for price", "-5", -5, True, float("nan"), float("inf"),
    "1,2,3", "12.34.56", "1.2345,6789", [], {}, "free",
])
def test_parse_price_rejects_ambiguous_or_invalid(raw):
    assert parse_price(raw) is None


@pytest.mark.parametrize("raw,expected", [("usd", "USD"), (" EUR ", "EUR"), ("$", None), ("US Dollar", None), (None, None), ("EURO", None)])
def test_currency(raw, expected):
    assert normalize_currency(raw) == expected


@pytest.mark.parametrize("raw,expected", [
    ("https://schema.org/InStock", "InStock"), ("http://schema.org/OutOfStock", "OutOfStock"),
    ("schema:PreOrder", "PreOrder"), ("InStock", "InStock"), ("in stock", "InStock"),
    ("out of stock", "OutOfStock"), ("BackOrder", "BackOrder"),
    ("maybe", None), ("", None), (None, None), ("Available soon", None),
])
def test_availability(raw, expected):
    assert normalize_availability(raw) == expected


@pytest.mark.parametrize("raw,expected", [
    ("/img/a.jpg", "https://shop.example.com/img/a.jpg"),
    ("//cdn.example.com/a.jpg", "https://cdn.example.com/a.jpg"),
    ({"@type": "ImageObject", "url": "https://x.com/a.jpg"}, "https://x.com/a.jpg"),
    (["", {"contentUrl": "/b.jpg"}], "https://shop.example.com/b.jpg"),
    ("javascript:alert(1)", None),
    ("data:image/png;base64,AAAA", None),
    (None, None),
])
def test_safe_url(raw, expected):
    assert safe_url(raw, PAGE) == expected


# ------------------------------------------------------------------ Product mapping
def test_full_product_mapping():
    node = parse_jsonld_text("""{
      "@type": "Product", "name": "Stoneware &amp; Mug", "description": "<p>Hand <b>made</b></p>",
      "image": [{"@type": "ImageObject", "url": "/img/mug.jpg"}], "sku": "MUG-1",
      "brand": {"@type": "Brand", "name": "Clay Co"}, "category": "Kitchen > Mugs",
      "weight": {"@type": "QuantitativeValue", "value": 350, "unitCode": "GRM"},
      "additionalProperty": [{"@type": "PropertyValue", "name": "Capacity", "value": "350 ml"}],
      "offers": {"@type": "Offer", "price": "18.00", "priceCurrency": "gbp",
                 "availability": "https://schema.org/InStock", "url": "/products/mug"}
    }""")[0]
    p = product_from_jsonld(node, PAGE)
    assert p.name == "Stoneware & Mug"
    assert p.description == "Hand made"
    assert (p.price, p.currency, p.availability) == (18.0, "GBP", "InStock")
    assert p.category == "Kitchen > Mugs"
    assert p.image_url == "https://shop.example.com/img/mug.jpg"
    assert p.product_url == PAGE
    assert p.specifications == {"brand": "Clay Co", "sku": "MUG-1", "weight": "350 GRM", "Capacity": "350 ml"}


def test_missing_fields_stay_null_never_fabricated():
    p = product_from_jsonld({"@type": "Product", "name": "Bare"}, None)
    assert p.model_dump() == {
        "name": "Bare", "description": None, "price": None, "currency": None, "category": None,
        "specifications": {}, "image_url": None, "product_url": None, "availability": None,
    }


def test_currency_dropped_when_price_missing():
    p = product_from_jsonld({"@type": "Product", "name": "X", "offers": {"price": "Call us", "priceCurrency": "USD"}}, PAGE)
    assert p.price is None and p.currency is None


def test_invalid_availability_and_currency_become_null():
    p = product_from_jsonld({"@type": "Product", "name": "X",
                             "offers": {"price": 5, "priceCurrency": "$", "availability": "ask us"}}, PAGE)
    assert p.price == 5.0 and p.currency is None and p.availability is None


def test_product_without_name_dropped():
    assert product_from_jsonld({"@type": "Product", "offers": {"price": 5}}, PAGE) is None
    assert product_from_jsonld({"@type": "Product", "name": "   "}, PAGE) is None


def test_aggregate_offer_uses_low_price():
    p = product_from_jsonld({"@type": "Product", "name": "X", "offers": {
        "@type": "AggregateOffer", "lowPrice": "10.00", "highPrice": "20.00", "priceCurrency": "USD"}}, PAGE)
    assert p.price == 10.0 and p.currency == "USD"


def test_price_specification():
    p = product_from_jsonld({"@type": "Product", "name": "X", "offers": {"@type": "Offer",
        "priceSpecification": {"@type": "UnitPriceSpecification", "price": 7.5, "priceCurrency": "EUR"}}}, PAGE)
    assert (p.price, p.currency) == (7.5, "EUR")


def test_product_group_variant_offers_and_availability_aggregation():
    node = {"@type": "ProductGroup", "name": "Leggings", "hasVariant": [
        {"@type": "Product", "offers": {"price": 9, "priceCurrency": "USD", "availability": "https://schema.org/OutOfStock"}},
        {"@type": "Product", "offers": {"price": 9, "priceCurrency": "USD", "availability": "https://schema.org/InStock"}},
    ]}
    p = product_from_jsonld(node, PAGE)
    assert (p.price, p.currency, p.availability) == (9.0, "USD", "InStock")
    assert p.specifications["variant_count"] == 2


def test_all_variants_out_of_stock():
    node = {"@type": "ProductGroup", "name": "X", "hasVariant": [
        {"offers": {"price": 1, "availability": "OutOfStock"}}, {"offers": {"price": 1, "availability": "OutOfStock"}}]}
    assert product_from_jsonld(node, PAGE).availability == "OutOfStock"


def test_javascript_image_url_rejected():
    p = product_from_jsonld({"@type": "Product", "name": "X", "image": "javascript:alert(1)"}, PAGE)
    assert p.image_url is None


def test_description_truncated():
    p = product_from_jsonld({"@type": "Product", "name": "X", "description": "a " * 2000}, PAGE)
    assert len(p.description) == 1000 and p.description.endswith("…")


# ------------------------------------------------------------------ OpenGraph fallback
def test_opengraph_product():
    html = """<meta property="og:type" content="product"><meta property="og:title" content="OG Mug">
    <meta property="product:price:amount" content="12.50"><meta property="product:price:currency" content="usd">
    <meta property="og:image" content="/m.jpg">"""
    p = product_from_opengraph(html, PAGE)
    assert (p.name, p.price, p.currency, p.availability) == ("OG Mug", 12.5, "USD", None)
    assert p.image_url == "https://shop.example.com/m.jpg"


def test_opengraph_ignored_for_non_product_pages():
    html = '<meta property="og:type" content="website"><meta property="og:title" content="Home">'
    assert product_from_opengraph(html, PAGE) is None


def test_visible_price_text_is_never_scraped():
    html = "<html><body><h1>Mug</h1><span class='price'>$19.99</span><button>Add to cart</button></body></html>"
    products, _ = products_from_html(html, PAGE, 5)
    assert products == []


def test_jsonld_preferred_over_opengraph():
    html = ld('{"@type":"Product","name":"From JSON-LD"}') + '<meta property="og:type" content="product"><meta property="og:title" content="From OG">'
    products, _ = products_from_html(html, PAGE, 5)
    assert [p.name for p in products] == ["From JSON-LD"]


def test_price_is_finite():
    p = product_from_jsonld({"@type": "Product", "name": "X", "offers": {"price": "1e400"}}, PAGE)
    assert p.price is None or math.isfinite(p.price)
