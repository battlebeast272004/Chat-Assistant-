"""Sample product extraction (max 5) from the highest-priority accessible source.

Priority: Public platform API  >  JSON-LD on homepage/catalog  >  Sitemap -> product pages (HTML)

If the top source yields no valid products, the next one is tried, and every
attempt is recorded. Mapping rules:

* Shopify /products.json has no currency field, so ``currency`` stays None.
  Availability comes only from variant ``available`` flags.
* WooCommerce Store API prices are integer strings in minor units; they are
  divided by 10**currency_minor_unit, and are None if either part is missing.
* JSON-LD / OpenGraph: see services/structured_data.py.
* An item without a name is dropped. A field that fails validation becomes None.
"""

from __future__ import annotations

from typing import Any, Callable

from models.product import MAX_PRODUCTS, ExtractionAttempt, ExtractionResult, Product, compute_field_coverage
from models.source import EXTRACTABLE, PAGE_SAMPLING, DiscoveredSource, SourceDiscoveryResult, SourceType
from services.platform_detector import PlatformDetectionResult
from services.source_detector import ProbeContext, discover_sources, parse_json
from services.structured_data import (
    MAX_DESCRIPTION_CHARS,
    MAX_SPEC_VALUE_CHARS,
    build_product,
    clean_text,
    normalize_currency,
    parse_price,
    products_from_html,
    safe_url,
)
from services.url_validator import FetchResult

EXTRACTION_EXTRA_BUDGET_S = 20.0
MAX_PAGES_TO_FETCH = 8


# ======================================================================
# Platform API mappers
# ======================================================================
def map_shopify_product(item: dict, base_url: str) -> Product | None:
    variants = [v for v in item.get("variants") or [] if isinstance(v, dict)]
    first = variants[0] if variants else {}

    flags = [v["available"] for v in variants if isinstance(v.get("available"), bool)]
    availability = None
    if flags:
        availability = "InStock" if any(flags) else "OutOfStock"

    images = [i for i in item.get("images") or [] if isinstance(i, dict)]
    options = {}
    for opt in item.get("options") or []:
        if isinstance(opt, dict) and opt.get("name") and opt.get("values"):
            name = clean_text(opt["name"], 80)
            # Shopify's placeholder option ("Title" = ["Default Title"]) carries no information.
            if name and opt["values"] != ["Default Title"]:
                options[name] = [clean_text(x, MAX_SPEC_VALUE_CHARS) for x in opt["values"] if clean_text(x)]

    tags = item.get("tags")
    if isinstance(tags, str):
        tags = [t.strip() for t in tags.split(",") if t.strip()]
    handle = item.get("handle")
    return build_product({
        "name": clean_text(item.get("title"), 300),
        "description": clean_text(item.get("body_html"), MAX_DESCRIPTION_CHARS),
        "price": parse_price(first.get("price")),
        "currency": None,  # not present in /products.json
        "category": clean_text(item.get("product_type"), 200),
        "specifications": {
            "vendor": clean_text(item.get("vendor"), MAX_SPEC_VALUE_CHARS),
            "sku": clean_text(first.get("sku"), MAX_SPEC_VALUE_CHARS),
            "options": options or None,
            "variant_count": len(variants) or None,
            "tags": (tags[:20] if isinstance(tags, list) else None) or None,
        },
        "image_url": safe_url(images[0].get("src") if images else None, base_url),
        "product_url": safe_url(f"/products/{handle}", base_url) if isinstance(handle, str) and handle else None,
        "availability": availability,
    })


def map_woo_product(item: dict, base_url: str) -> Product | None:
    prices = item.get("prices") if isinstance(item.get("prices"), dict) else {}
    price = None
    raw_price, minor = prices.get("price"), prices.get("currency_minor_unit")
    if isinstance(raw_price, str) and raw_price.isdigit() and isinstance(minor, int) and 0 <= minor <= 4:
        price = int(raw_price) / (10 ** minor)

    if item.get("is_on_backorder") is True:
        availability = "BackOrder"
    elif isinstance(item.get("is_in_stock"), bool):
        availability = "InStock" if item["is_in_stock"] else "OutOfStock"
    else:
        availability = None

    categories = [c for c in item.get("categories") or [] if isinstance(c, dict)]
    images = [i for i in item.get("images") or [] if isinstance(i, dict)]
    attributes = {}
    for attr in item.get("attributes") or []:
        if isinstance(attr, dict) and attr.get("name"):
            terms = [clean_text(t.get("name"), MAX_SPEC_VALUE_CHARS) for t in attr.get("terms") or [] if isinstance(t, dict)]
            terms = [t for t in terms if t]
            if terms:
                attributes[clean_text(attr["name"], 80)] = terms

    return build_product({
        "name": clean_text(item.get("name"), 300),
        "description": clean_text(item.get("short_description") or item.get("description"), MAX_DESCRIPTION_CHARS),
        "price": price,
        "currency": normalize_currency(prices.get("currency_code")) if price is not None else None,
        "category": clean_text(categories[0].get("name"), 200) if categories else None,
        "specifications": {"sku": clean_text(item.get("sku"), MAX_SPEC_VALUE_CHARS), **attributes},
        "image_url": safe_url(images[0].get("src") if images else None, base_url),
        "product_url": safe_url(item.get("permalink"), base_url),
        "availability": availability,
    })


# ======================================================================
# Per-source extractors -> (products, warnings)
# ======================================================================
Extractor = Callable[[DiscoveredSource, ProbeContext, str], tuple[list[Product], list[str]]]


def _from_api(mapper: Callable[[dict, str], Product | None], key: str | None) -> Extractor:
    def run(src: DiscoveredSource, ctx: ProbeContext, base: str) -> tuple[list[Product], list[str]]:
        data = parse_json(ctx.cache.get(src.source_url))
        items = data.get(key) if (key and isinstance(data, dict)) else data
        if not isinstance(items, list):
            return [], ["API payload was not a list of products."]
        products, dropped = [], 0
        for item in items:
            if not isinstance(item, dict):
                continue
            product = mapper(item, base)
            if product:
                products.append(product)
            else:
                dropped += 1
            if len(products) >= MAX_PRODUCTS:
                break
        return products, ([f"{dropped} API item(s) skipped: no product name."] if dropped else [])
    return run


def _from_jsonld(src: DiscoveredSource, ctx: ProbeContext, base: str) -> tuple[list[Product], list[str]]:
    fetch: FetchResult | None = ctx.cache.get(src.source_url)
    if fetch is None:  # homepage is cached under the submitted URL, so look it up by final URL
        fetch = next((f for f in ctx.cache.values() if f.result.final_url == src.source_url), None)
    if not fetch or not fetch.html:
        return [], ["Page HTML no longer available."]
    return products_from_html(fetch.html, fetch.result.final_url, MAX_PRODUCTS)


def _from_sitemap_pages(src: DiscoveredSource, ctx: ProbeContext, base: str) -> tuple[list[Product], list[str]]:
    urls = src.sample_urls[:MAX_PAGES_TO_FETCH]
    if not urls:
        return [], ["Source contained no product-like URLs to sample."]
    products: list[Product] = []
    warnings: list[str] = []
    no_data = 0
    # Fetch the first MAX_PRODUCTS pages; only fetch the rest if some had no data.
    for batch in (urls[:MAX_PRODUCTS], urls[MAX_PRODUCTS:]):
        if not batch or len(products) >= MAX_PRODUCTS:
            break
        pages = ctx.fetch_many([(u, "product page", {}) for u in batch])
        for url in batch:  # keep source order, which makes the output deterministic
            fetch = pages.get(url)
            if not fetch or not fetch.html or fetch.result.http_status != 200:
                continue
            found, warn = products_from_html(fetch.html, fetch.result.final_url, 1)
            warnings.extend(warn)
            if found:
                products.append(found[0])
            else:
                no_data += 1
            if len(products) >= MAX_PRODUCTS:
                break
    if no_data:
        warnings.append(f"{no_data} sampled page(s) had no schema.org Product JSON-LD or OpenGraph product tags.")
    return products, warnings


EXTRACTORS: dict[SourceType, Extractor] = {
    SourceType.SHOPIFY_PRODUCTS_JSON: _from_api(map_shopify_product, "products"),
    SourceType.WOOCOMMERCE_STORE_API: _from_api(map_woo_product, None),
    SourceType.JSON_LD: _from_jsonld,
    SourceType.PRODUCT_SITEMAP: _from_sitemap_pages,
    SourceType.HTML_PRODUCT_PAGES: _from_sitemap_pages,
    SourceType.SITEMAP: _from_sitemap_pages,
}


def _dedupe(products: list[Product]) -> list[Product]:
    seen, out = set(), []
    for p in products:
        key = p.product_url or p.name
        if key not in seen:
            seen.add(key)
            out.append(p)
    return out


def extract_from_discovery(discovery: SourceDiscoveryResult, ctx: ProbeContext) -> ExtractionResult:
    result = ExtractionResult()
    if not discovery.base_url:
        result.warnings.append("No reachable site to extract from.")
        return result

    candidates = [s for s in discovery.sources if s.accessible and s.source_type in EXTRACTABLE
                  and (s.source_type not in PAGE_SAMPLING or s.sample_urls)]
    candidates.sort(key=lambda s: s.priority)  # stable: keeps discovery order within a priority
    if not candidates:
        result.warnings.append("No accessible product data source was found.")
        return result

    ctx.extend(EXTRACTION_EXTRA_BUDGET_S)
    for src in candidates:
        try:
            products, warnings = EXTRACTORS[src.source_type](src, ctx, discovery.base_url)
            error = None
        except Exception as exc:  # one broken source must not break the whole report
            products, warnings, error = [], [], f"{type(exc).__name__} while extracting"
        products = _dedupe(products)[:MAX_PRODUCTS]
        result.attempts.append(ExtractionAttempt(
            source_type=src.source_type.value, source_url=src.source_url,
            products_extracted=len(products), error=error or (None if products else "No valid products extracted."),
        ))
        result.warnings.extend(w for w in warnings if w not in result.warnings)
        if products:
            result.source_type, result.source_url = src.source_type.value, src.source_url
            result.products = products
            result.items_extracted = len(products)
            result.field_coverage = compute_field_coverage(products)
            break
    if not result.products:
        result.warnings.append("No products could be extracted from any accessible source.")
    return result


def extract_products(
    raw_url: str,
) -> tuple[FetchResult, PlatformDetectionResult | None, SourceDiscoveryResult, ExtractionResult]:
    home, platform, discovery, ctx = discover_sources(raw_url)
    extraction = extract_from_discovery(discovery, ctx)
    discovery.probes = list(ctx.probes)  # include requests made during extraction
    return home, platform, discovery, extraction
