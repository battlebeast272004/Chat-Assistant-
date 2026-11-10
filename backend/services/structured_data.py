"""Tolerant JSON-LD / OpenGraph parsing and strict value normalization.

Rules:
- Repairs are limited to *syntactic* wrapping that CMSs commonly add (HTML
  comments, CDATA, trailing commas, concatenated objects, raw newlines inside
  strings). If a block still won't parse, it's skipped and a warning is
  recorded. We never "guess" what a broken block meant.
- Normalizers return None when a value is missing, ambiguous or invalid.
  A price of "Call us" becomes None, not 0. An availability of "maybe" becomes None.
"""

from __future__ import annotations

import html as html_lib
import json
import math
import re
from collections.abc import Iterator
from typing import Any
from urllib.parse import urljoin

from bs4 import BeautifulSoup
from pydantic import ValidationError

from models.product import AVAILABILITY_VALUES, Product

MAX_DESCRIPTION_CHARS = 1000
MAX_SPEC_VALUE_CHARS = 200
MAX_JSONLD_BLOCKS = 50
MAX_JSONLD_BLOCK_CHARS = 1_000_000
MAX_WALK_DEPTH = 12
MAX_WALK_NODES = 5000

_SCHEMA_PREFIX = re.compile(r"^(https?://schema\.org/|schema:)", re.IGNORECASE)
_TRAILING_COMMA = re.compile(r",\s*([}\]])")
_WS = re.compile(r"\s+")


# ======================================================================
# JSON-LD block extraction with repair
# ======================================================================
def _strip_wrappers(text: str) -> str:
    t = text.strip().lstrip("﻿").strip()
    # <!-- ... -->
    if t.startswith("<!--"):
        t = t[4:]
        if t.rstrip().endswith("-->"):
            t = t.rstrip()[:-3]
    # //<![CDATA[ ... //]]>  or  /*<![CDATA[*/ ... /*]]>*/
    t = re.sub(r"^\s*(//|/\*)?\s*<!\[CDATA\[\s*(\*/)?", "", t)
    t = re.sub(r"(//|/\*)?\s*\]\]>\s*(\*/)?\s*$", "", t)
    return t.strip().rstrip(";").strip()


def _decode_all(text: str) -> list[Any]:
    """Decode one or more concatenated JSON values (``{...}{...}`` or ``{...}\\n{...}``)."""
    decoder = json.JSONDecoder(strict=False)  # strict=False allows raw control chars in strings
    values, idx = [], 0
    while idx < len(text):
        while idx < len(text) and text[idx] in " \t\r\n,;":
            idx += 1
        if idx >= len(text):
            break
        value, idx = decoder.raw_decode(text, idx)
        values.append(value)
    return values


def parse_jsonld_text(text: str) -> list[Any]:
    """Parse a JSON-LD script body. Raises ValueError if it can't be repaired."""
    if len(text) > MAX_JSONLD_BLOCK_CHARS:
        raise ValueError("JSON-LD block too large")
    cleaned = _strip_wrappers(text)
    if not cleaned:
        raise ValueError("empty JSON-LD block")
    attempts = (cleaned, _TRAILING_COMMA.sub(r"\1", cleaned))
    last: Exception | None = None
    for candidate in attempts:
        try:
            values = _decode_all(candidate)
            if values:
                return values
        except (json.JSONDecodeError, RecursionError) as exc:
            last = exc
    raise ValueError(f"malformed JSON-LD: {last}")


def extract_jsonld(html: str) -> tuple[list[Any], list[str]]:
    """Return (parsed top-level JSON values, warnings) from every ld+json script."""
    if not html:
        return [], []
    soup = BeautifulSoup(html, "html.parser")
    scripts = soup.find_all("script", attrs={"type": re.compile(r"application/ld\+json", re.I)})
    values: list[Any] = []
    malformed = 0
    for script in scripts[:MAX_JSONLD_BLOCKS]:
        text = script.string if script.string is not None else script.get_text()
        try:
            values.extend(parse_jsonld_text(text or ""))
        except ValueError:
            malformed += 1
    warnings = []
    if malformed:
        warnings.append(f"{malformed} JSON-LD block(s) could not be parsed and were skipped.")
    if len(scripts) > MAX_JSONLD_BLOCKS:
        warnings.append(f"Only the first {MAX_JSONLD_BLOCKS} JSON-LD blocks were inspected.")
    return values, warnings


# ======================================================================
# Graph walking
# ======================================================================
def _types(node: dict) -> set[str]:
    raw = node.get("@type", [])
    raw = raw if isinstance(raw, list) else [raw]
    return {_SCHEMA_PREFIX.sub("", t).strip() for t in raw if isinstance(t, str)}


def is_type(node: Any, *names: str) -> bool:
    return isinstance(node, dict) and bool(_types(node) & set(names))


def iter_product_nodes(values: list[Any]) -> Iterator[dict]:
    """Yield Product / ProductGroup nodes anywhere in the JSON-LD (including
    @graph, ItemList.itemListElement[].item, mainEntity, ...).

    We don't descend into a Product once found, so related products, variants
    and accessories aren't emitted as separate items. A ProductGroup is emitted
    once (its variants are only used as a fallback for offers).
    """
    seen = 0

    def walk(node: Any, depth: int) -> Iterator[dict]:
        nonlocal seen
        seen += 1
        if depth > MAX_WALK_DEPTH or seen > MAX_WALK_NODES:
            return
        if isinstance(node, list):
            for item in node:
                yield from walk(item, depth + 1)
        elif isinstance(node, dict):
            if is_type(node, "Product", "ProductGroup", "IndividualProduct", "ProductModel"):
                yield node
                return
            for key, value in node.items():
                if key in ("@context",):
                    continue
                if isinstance(value, (dict, list)):
                    yield from walk(value, depth + 1)

    for value in values:
        yield from walk(value, 0)


def count_jsonld_products(html: str) -> tuple[int, list[str]]:
    values, warnings = extract_jsonld(html)
    return sum(1 for _ in iter_product_nodes(values)), warnings


# ======================================================================
# Value normalizers (return None instead of guessing)
# ======================================================================
def clean_text(value: Any, limit: int | None = None) -> str | None:
    """Plain text from a string that may contain HTML/entities. Truncates to ``limit``."""
    text = first_text(value)
    if text is None:
        return None
    if "<" in text and ">" in text:
        text = BeautifulSoup(text, "html.parser").get_text(" ")
    text = _WS.sub(" ", html_lib.unescape(text)).strip()
    if not text:
        return None
    if limit and len(text) > limit:
        text = text[: limit - 1].rstrip() + "…"
    return text


def first_text(value: Any) -> str | None:
    """First textual value from str | number | {"@value"/"name"} | list."""
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, str):
        return value if value.strip() else None
    if isinstance(value, (int, float)):
        return str(value) if math.isfinite(value) else None
    if isinstance(value, dict):
        for key in ("@value", "name", "value"):
            if key in value:
                return first_text(value[key])
        return None
    if isinstance(value, list):
        for item in value:
            text = first_text(item)
            if text:
                return text
    return None


_NUM_IN_STRING = re.compile(r"^[^\d\-]{0,8}?(-?\d[\d.,\s  ']*)[^\d]{0,8}$")


def parse_price(value: Any) -> float | None:
    """Parse a price conservatively. Ambiguous or invalid values give None.

    Accepted:  19.99 | "19.99" | "$19.99" | "1,299.00" | "1.299,00" | "19,99" | "1 299.00"
    Rejected:  "" | "Call for price" | "-5" | "1,2,3" | NaN | inf | True
    A comma followed by exactly three digits ("1,299") is read as a thousands
    separator, matching schema.org's rule that prices use "." for decimals.
    """
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return float(value) if math.isfinite(value) and value >= 0 else None
    if isinstance(value, dict):
        return parse_price(value.get("@value", value.get("value")))
    if not isinstance(value, str):
        return None
    m = _NUM_IN_STRING.match(value.strip())
    if not m:
        return None
    num = re.sub(r"[\s  ']", "", m.group(1))
    if num.startswith("-"):
        return None
    if re.fullmatch(r"\d+(\.\d+)?", num):
        out = num
    elif re.fullmatch(r"\d{1,3}(,\d{3})+(\.\d+)?", num):          # 1,299.00
        out = num.replace(",", "")
    elif re.fullmatch(r"\d{1,3}(\.\d{3})+,\d{1,2}", num):          # 1.299,00
        out = num.replace(".", "").replace(",", ".")
    elif re.fullmatch(r"\d+,\d{1,2}", num):                         # 19,99
        out = num.replace(",", ".")
    else:
        return None
    result = float(out)
    return result if math.isfinite(result) else None


def normalize_currency(value: Any) -> str | None:
    text = first_text(value)
    if not text:
        return None
    text = text.strip().upper()
    return text if re.fullmatch(r"[A-Z]{3}", text) else None


_AVAILABILITY_LOOKUP = {v.lower(): v for v in AVAILABILITY_VALUES} | {
    "instock": "InStock", "in stock": "InStock", "available": "InStock",
    "outofstock": "OutOfStock", "out of stock": "OutOfStock", "oos": "OutOfStock",
    "preorder": "PreOrder", "pre-order": "PreOrder", "pre order": "PreOrder",
    "backorder": "BackOrder", "on backorder": "BackOrder",
    "soldout": "SoldOut", "sold out": "SoldOut", "discontinued": "Discontinued",
}


def normalize_availability(value: Any) -> str | None:
    text = first_text(value)
    if not text:
        return None
    token = _SCHEMA_PREFIX.sub("", text.strip()).rsplit("/", 1)[-1].strip().lower()
    return _AVAILABILITY_LOOKUP.get(token) or _AVAILABILITY_LOOKUP.get(token.replace("_", " "))


def safe_url(value: Any, base: str | None) -> str | None:
    """Absolute http(s) URL or None (rejects javascript:, data:, etc.)."""
    if isinstance(value, dict):
        value = value.get("url") or value.get("contentUrl") or value.get("@id")
    if isinstance(value, list):
        for item in value:
            url = safe_url(item, base)
            if url:
                return url
        return None
    if not isinstance(value, str) or not value.strip():
        return None
    raw = value.strip()
    if raw.startswith("//"):
        raw = "https:" + raw
    absolute = urljoin(base, raw) if base else raw
    return absolute if re.match(r"^https?://[^\s/]+", absolute, re.I) and len(absolute) <= 2048 else None


def _spec_value(value: Any) -> Any:
    if isinstance(value, dict):
        if is_type(value, "QuantitativeValue") or "unitCode" in value or "unitText" in value:
            num = first_text(value.get("value"))
            unit = first_text(value.get("unitText") or value.get("unitCode"))
            return " ".join(x for x in (num, unit) if x) or None
        return clean_text(value, MAX_SPEC_VALUE_CHARS)
    if isinstance(value, list):
        items = [v for v in (_spec_value(x) for x in value) if v]
        return items or None
    return clean_text(value, MAX_SPEC_VALUE_CHARS)


def build_product(fields: dict[str, Any]) -> Product | None:
    """Construct a Product. Any invalid field is set to None (never coerced),
    and items without a name are dropped."""
    data = {k: v for k, v in fields.items() if k in Product.model_fields}
    data["specifications"] = {k: v for k, v in (data.get("specifications") or {}).items() if v not in (None, "", [], {})}
    if not data.get("name"):
        return None
    for _ in range(len(data)):
        try:
            return Product(**data)
        except ValidationError as exc:
            bad = {err["loc"][0] for err in exc.errors() if err.get("loc")}
            if not bad or "name" in bad:
                return None
            for key in bad:
                data[key] = {} if key == "specifications" else None
    return None


# ======================================================================
# JSON-LD Product -> Product
# ======================================================================
def _offers(node: dict) -> list[dict]:
    raw = node.get("offers")
    items = raw if isinstance(raw, list) else [raw] if raw else []
    out: list[dict] = []
    for offer in items:
        if not isinstance(offer, dict):
            continue
        out.append(offer)
        nested = offer.get("offers")  # AggregateOffer.offers
        if isinstance(nested, (list, dict)):
            out.extend(o for o in (nested if isinstance(nested, list) else [nested]) if isinstance(o, dict))
    return out


def _price_from_offer(offer: dict) -> tuple[float | None, str | None]:
    price = parse_price(offer.get("price"))
    if price is None and is_type(offer, "AggregateOffer"):
        price = parse_price(offer.get("lowPrice"))
    currency = normalize_currency(offer.get("priceCurrency"))
    if price is None or currency is None:
        specs = offer.get("priceSpecification")
        for spec in specs if isinstance(specs, list) else [specs]:
            if isinstance(spec, dict):
                price = price if price is not None else parse_price(spec.get("price"))
                currency = currency or normalize_currency(spec.get("priceCurrency"))
    return price, currency


def product_from_jsonld(node: dict, page_url: str | None) -> Product | None:
    offers = _offers(node)
    if not offers and is_type(node, "ProductGroup"):
        variants = node.get("hasVariant")
        for variant in variants if isinstance(variants, list) else [variants]:
            if isinstance(variant, dict):
                offers.extend(_offers(variant))

    price = currency = None
    for offer in offers:  # price: the first offer that states one
        p, c = _price_from_offer(offer)
        if p is not None:
            price, currency = p, c
            break
    # Availability: InStock if ANY offer/variant is in stock (the product can be
    # bought), otherwise the first stated value. Never inferred when absent.
    states = [s for s in (normalize_availability(o.get("availability")) for o in offers) if s]
    availability = "InStock" if "InStock" in states else (states[0] if states else None)

    specs: dict[str, Any] = {
        "brand": clean_text(node.get("brand"), MAX_SPEC_VALUE_CHARS),
        "sku": clean_text(node.get("sku"), MAX_SPEC_VALUE_CHARS),
        "mpn": clean_text(node.get("mpn"), MAX_SPEC_VALUE_CHARS),
        "gtin": clean_text(next((node[k] for k in ("gtin", "gtin13", "gtin12", "gtin14", "gtin8") if node.get(k)), None)),
        "color": _spec_value(node.get("color")),
        "material": _spec_value(node.get("material")),
        "size": _spec_value(node.get("size")),
        "model": _spec_value(node.get("model")),
        "weight": _spec_value(node.get("weight")),
    }
    props = node.get("additionalProperty")
    for prop in props if isinstance(props, list) else [props]:
        if isinstance(prop, dict):
            key = clean_text(prop.get("name"), 80)
            val = _spec_value(prop.get("value"))
            if key and val and key not in specs:
                specs[key] = val
    variants = node.get("hasVariant")
    if isinstance(variants, list) and variants:
        specs["variant_count"] = len(variants)

    return build_product({
        "name": clean_text(node.get("name"), 300),
        "description": clean_text(node.get("description"), MAX_DESCRIPTION_CHARS),
        "price": price,
        "currency": currency if price is not None else None,  # a currency without a price is meaningless
        "category": clean_text(node.get("category"), 200),
        "specifications": specs,
        "image_url": safe_url(node.get("image"), page_url),
        "product_url": safe_url(node.get("url"), page_url) or safe_url(page_url, None),
        "availability": availability,
    })


# ======================================================================
# OpenGraph product tags -> Product (fallback for HTML pages)
# ======================================================================
def product_from_opengraph(html: str, page_url: str | None) -> Product | None:
    """Only used when a page declares itself a product (og:type=product or
    product:price:* tags). Visible page text is never scraped for prices."""
    soup = BeautifulSoup(html, "html.parser")
    meta: dict[str, str] = {}
    for tag in soup.find_all("meta"):
        key = (tag.get("property") or tag.get("name") or "").strip().lower()
        if key and key not in meta and tag.get("content") is not None:
            meta[key] = str(tag["content"])
    is_product = meta.get("og:type", "").lower().startswith("product") or "product:price:amount" in meta
    if not is_product:
        return None
    price = parse_price(meta.get("product:price:amount") or meta.get("og:price:amount"))
    currency = normalize_currency(meta.get("product:price:currency") or meta.get("og:price:currency"))
    return build_product({
        "name": clean_text(meta.get("og:title"), 300),
        "description": clean_text(meta.get("og:description"), MAX_DESCRIPTION_CHARS),
        "price": price,
        "currency": currency if price is not None else None,
        "category": clean_text(meta.get("product:category"), 200),
        "specifications": {
            "brand": clean_text(meta.get("product:brand"), MAX_SPEC_VALUE_CHARS),
            "sku": clean_text(meta.get("product:retailer_item_id"), MAX_SPEC_VALUE_CHARS),
        },
        "image_url": safe_url(meta.get("og:image"), page_url),
        "product_url": safe_url(meta.get("og:url"), page_url) or safe_url(page_url, None),
        "availability": normalize_availability(meta.get("product:availability") or meta.get("og:availability")),
    })


def products_from_html(html: str, page_url: str | None, limit: int) -> tuple[list[Product], list[str]]:
    """JSON-LD products first; OpenGraph only if the page has no JSON-LD product."""
    values, warnings = extract_jsonld(html)
    products: list[Product] = []
    for node in iter_product_nodes(values):
        product = product_from_jsonld(node, page_url)
        if product:
            products.append(product)
        if len(products) >= limit:
            break
    if not products:
        og = product_from_opengraph(html, page_url)
        if og:
            products.append(og)
    return products, warnings
